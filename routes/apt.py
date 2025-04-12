from flask import Blueprint, render_template, request, jsonify, current_app, flash, redirect, url_for, session
import logging
import json
import threading
from modules.apt_simulator import APTSimulator
from models import Scan, Report, Vulnerability, db
from datetime import datetime

apt_bp = Blueprint('apt_bp', __name__)
logger = logging.getLogger(__name__)

@apt_bp.route('/apt-dashboard')
def apt_dashboard():
    """
    Render the APT dashboard
    """
    # Get available scenarios from APT module
    apt_sim = APTSimulator()
    scenarios = apt_sim.get_scenarios()
    techniques = apt_sim.get_techniques()
    
    # Get past APT simulations if any
    apt_scans = Scan.query.filter(Scan.modules_run.like('%apt_simulator%')).order_by(Scan.scan_date.desc()).limit(5).all()
    
    return render_template(
        'apt_dashboard.html',
        scenarios=scenarios,
        techniques=techniques,
        recent_scans=apt_scans
    )

@apt_bp.route('/apt-simulator', methods=['GET', 'POST'])
def apt_simulator():
    """
    Configure and run APT simulation
    """
    apt_sim = APTSimulator()
    scenarios = apt_sim.get_scenarios()
    techniques = apt_sim.get_techniques()
    
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        scenario = request.form.get('scenario', 'default')
        intensity = request.form.get('intensity', 'medium')
        
        # Get selected techniques from form
        selected_techniques = []
        for phase in techniques:
            for technique in techniques[phase]:
                technique_id = f"{phase}_{technique.lower().replace(' ', '_')}"
                if request.form.get(technique_id) == 'on':
                    selected_techniques.append(f"{phase}.{technique}")
        
        # Create a new scan record
        scan = Scan(
            target_url=target_url,
            scan_date=datetime.utcnow(),
            status='pending',
            user_id=session.get('user_id')  # If using authentication
        )
        
        # Set modules
        modules = ['apt_simulator']
        scan.set_modules(modules)
        
        # Save scan to database
        db.session.add(scan)
        db.session.commit()
        
        # Create configuration for the simulation
        config = {
            'url': target_url,
            'scenario': scenario,
            'intensity': intensity,
            'techniques': selected_techniques
        }
        
        # Start APT simulation in background thread
        thread = threading.Thread(
            target=run_apt_simulation,
            args=(scan.id, config)
        )
        thread.daemon = True
        thread.start()
        
        flash('APT simulation started. This may take several minutes to complete.', 'info')
        return redirect(url_for('apt_bp.apt_status', scan_id=scan.id))
    
    return render_template(
        'apt_simulator.html',
        scenarios=scenarios,
        techniques=techniques
    )

@apt_bp.route('/apt-status/<int:scan_id>')
def apt_status(scan_id):
    """
    Show status of APT simulation
    """
    scan = Scan.query.get_or_404(scan_id)
    
    return render_template(
        'apt_status.html',
        scan=scan
    )

@apt_bp.route('/api/apt-status/<int:scan_id>')
def apt_status_api(scan_id):
    """
    API endpoint to get APT simulation status
    """
    try:
        scan = Scan.query.get_or_404(scan_id)
        
        # Check if the simulation has a report
        report_data = None
        if scan.report:
            vulnerabilities = scan.report.vulnerabilities.all()
            vuln_count_by_severity = {}
            for vuln in vulnerabilities:
                if vuln.severity not in vuln_count_by_severity:
                    vuln_count_by_severity[vuln.severity] = 0
                vuln_count_by_severity[vuln.severity] += 1
            
            report_data = {
                'id': scan.report.id,
                'title': scan.report.title,
                'created_at': scan.report.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerability_counts': vuln_count_by_severity,
                'total_vulnerabilities': len(vulnerabilities)
            }
        
        return jsonify({
            'id': scan.id,
            'target_url': scan.target_url,
            'status': scan.status,
            'scan_date': scan.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
            'report': report_data
        })
    
    except Exception as e:
        logger.error(f"Error checking APT simulation status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@apt_bp.route('/apt-results/<int:report_id>')
def apt_results(report_id):
    """
    Show detailed results of an APT simulation
    """
    report = Report.query.get_or_404(report_id)
    vulnerabilities = report.vulnerabilities.all()
    
    # Group vulnerabilities by attack phase
    phases = {
        'initial_access': [],
        'persistence': [],
        'privilege_escalation': [],
        'lateral_movement': [],
        'data_exfiltration': []
    }
    
    other_vulnerabilities = []
    
    for vuln in vulnerabilities:
        # Determine phase based on vulnerability type or description
        assigned = False
        for phase in phases:
            if phase.upper() in vuln.type.upper() or phase.upper() in vuln.description.upper():
                phases[phase].append(vuln)
                assigned = True
                break
        
        if not assigned:
            other_vulnerabilities.append(vuln)
    
    return render_template(
        'apt_results.html',
        report=report,
        phases=phases,
        other_vulnerabilities=other_vulnerabilities
    )

@apt_bp.route('/apt-tactics')
def apt_tactics():
    """
    Educational page about APT tactics and techniques
    """
    apt_sim = APTSimulator()
    techniques = apt_sim.get_techniques()
    
    return render_template(
        'apt_tactics.html',
        techniques=techniques
    )

def run_apt_simulation(scan_id, config):
    """
    Background task to run the APT simulation
    """
    from app import app
    
    with app.app_context():
        try:
            # Get scan record
            scan = Scan.query.get(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
            
            # Update scan status
            scan.status = 'in_progress'
            db.session.commit()
            
            # Initialize APT simulator
            apt_sim = APTSimulator(config)
            
            # Run simulation - use the target URL as a single-item list
            urls = [config.get('url')]
            results = {'apt_simulator': apt_sim.scan(urls)}
            
            # Create report record
            report = Report(
                title=f"APT Simulation for {scan.target_url}",
                summary="Advanced Persistent Threat simulation results showing potential attack paths and vulnerabilities",
                created_at=datetime.utcnow(),
                user_id=scan.user_id
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
            logger.info(f"APT Simulation {scan_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error running APT simulation {scan_id}: {str(e)}")
            try:
                # Update scan status to failed
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.status = 'failed'
                    db.session.commit()
            except Exception as commit_error:
                logger.error(f"Error updating scan status: {str(commit_error)}")