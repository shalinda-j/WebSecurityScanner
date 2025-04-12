from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from models import Scan, Report, Vulnerability
from app import db
import logging
import urllib.parse
from datetime import datetime
import threading
import time
import json

# Import scanner modules
from modules.scanner_engine import ScannerEngine
from modules.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

scan_bp = Blueprint('scan_bp', __name__)

@scan_bp.route('/scan/new', methods=['GET'])
def new_scan():
    """
    Route for the new scan form
    """
    return render_template('scan_form.html')


@scan_bp.route('/scan/start', methods=['POST'])
def start_scan():
    """
    Route to start a new scan
    """
    try:
        # Get form data
        target_url = request.form.get('target_url')
        
        # Validate URL
        if not target_url or not target_url.startswith(('http://', 'https://')):
            flash("Invalid URL. Please enter a valid URL starting with http:// or https://", "danger")
            return redirect(url_for('scan_bp.new_scan'))
        
        # Get selected modules
        modules = request.form.getlist('modules')
        if not modules:
            flash("Please select at least one scan module", "danger")
            return redirect(url_for('scan_bp.new_scan'))
        
        # Get advanced options
        crawl_depth = int(request.form.get('crawl_depth', 2))
        request_timeout = int(request.form.get('request_timeout', 30))
        user_agent = request.form.get('user_agent', '')
        cookies = request.form.get('cookies', '')
        
        # Verify consent checkbox
        if 'consent' not in request.form:
            flash("You must confirm that you have authorization to scan this target", "danger")
            return redirect(url_for('scan_bp.new_scan'))
        
        # Create scan config
        config = {
            'url': target_url,
            'depth': crawl_depth,
            'timeout': request_timeout
        }
        
        if user_agent:
            config['user_agent'] = user_agent
        
        if cookies:
            config['cookies'] = cookies
        
        # Create scan record
        scan = Scan(
            target_url=target_url,
            status='in_progress',
            scan_date=datetime.utcnow()
        )
        
        # Set modules
        scan.set_modules(modules)
        
        # Save to DB
        db.session.add(scan)
        db.session.commit()
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan_task, args=(scan.id, config, modules))
        thread.daemon = True
        thread.start()
        
        flash(f"Scan started for {target_url}", "success")
        return redirect(url_for('scan_bp.view_scan_status', scan_id=scan.id))
    
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        flash(f"Error starting scan: {str(e)}", "danger")
        return redirect(url_for('scan_bp.new_scan'))


@scan_bp.route('/scan/<int:scan_id>/status')
def view_scan_status(scan_id):
    """
    Route to view scan status
    """
    try:
        scan = Scan.query.get_or_404(scan_id)
        return render_template('scan_results.html', scan=scan)
    
    except Exception as e:
        logger.error(f"Error viewing scan status: {str(e)}")
        flash(f"Error viewing scan status: {str(e)}", "danger")
        return redirect(url_for('dashboard_bp.index'))


@scan_bp.route('/scan/<int:scan_id>/status/check', methods=['GET'])
def check_scan_status(scan_id):
    """
    AJAX endpoint to check scan status
    """
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        response = {
            'status': scan.status,
            'report_id': scan.report_id if scan.report_id else None
        }
        
        return jsonify(response)
    
    except Exception as e:
        logger.error(f"Error checking scan status: {str(e)}")
        return jsonify({'error': str(e)}), 500


def run_scan_task(scan_id, config, modules):
    """
    Background task to run the scan
    """
    from app import app
    
    with app.app_context():
        try:
            # Get scan record
            scan = Scan.query.get(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
            
            # Initialize scanner
            scanner = ScannerEngine(config)
            
            # Run scan
            results = scanner.run_scan(modules)
            
            # Generate report
            report_generator = ReportGenerator()
            report_data = report_generator.generate_report(scan.target_url, results)
            
            # Create report record
            report = Report(
                title=f"Security Scan for {scan.target_url}",
                summary=report_data['executive_summary'],
                created_at=datetime.utcnow()
            )
            
            # Save report
            db.session.add(report)
            db.session.flush()  # Get report ID without committing
            
            # Update scan with report ID
            scan.report_id = report.id
            scan.status = 'completed'
            
            # Add vulnerabilities to the report
            for module_name, module_results in results.items():
                for vuln_data in module_results:
                    vulnerability = Vulnerability(
                        report_id=report.id,
                        type=vuln_data['type'],
                        severity=vuln_data['severity'],
                        description=vuln_data['description'],
                        location=vuln_data['location'],
                        proof=vuln_data.get('proof', ''),
                        remediation=vuln_data.get('remediation', '')
                    )
                    db.session.add(vulnerability)
            
            # Commit all changes
            db.session.commit()
            logger.info(f"Scan {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error running scan {scan_id}: {str(e)}")
            try:
                # Update scan status to failed
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.status = 'failed'
                    db.session.commit()
            except Exception as commit_error:
                logger.error(f"Error updating scan status: {str(commit_error)}")
