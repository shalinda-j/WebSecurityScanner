from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from models import Report, Vulnerability, Scan
from app import db
import logging
import json
from datetime import datetime
import io
import csv

logger = logging.getLogger(__name__)

reports_bp = Blueprint('reports_bp', __name__)

@reports_bp.route('/reports')
def list_reports():
    """
    Route to list all reports
    """
    try:
        reports = Report.query.order_by(Report.created_at.desc()).all()
        return render_template('reports.html', reports=reports)
    
    except Exception as e:
        logger.error(f"Error listing reports: {str(e)}")
        flash(f"Error listing reports: {str(e)}", "danger")
        return redirect(url_for('dashboard_bp.index'))


@reports_bp.route('/report/<int:report_id>')
def view_report(report_id):
    """
    Route to view a single report
    """
    try:
        report = Report.query.get_or_404(report_id)
        
        # Get vulnerabilities by severity for easy display
        vulnerabilities_by_severity = {}
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            vulnerabilities_by_severity[severity] = Vulnerability.query.filter_by(
                report_id=report_id, 
                severity=severity
            ).all()
        
        # Get related scan(s)
        related_scans = Scan.query.filter_by(report_id=report_id).all()
        
        return render_template(
            'report_detail.html', 
            report=report,
            vulnerabilities_by_severity=vulnerabilities_by_severity,
            related_scans=related_scans
        )
    
    except Exception as e:
        logger.error(f"Error viewing report: {str(e)}")
        flash(f"Error viewing report: {str(e)}", "danger")
        return redirect(url_for('reports_bp.list_reports'))


@reports_bp.route('/report/<int:report_id>/export', methods=['GET'])
def export_report(report_id):
    """
    Route to export a report in different formats
    """
    try:
        report = Report.query.get_or_404(report_id)
        export_format = request.args.get('format', 'json')
        
        if export_format == 'json':
            # Export as JSON
            report_data = report.to_dict()
            
            # Create a file-like object
            buffer = io.StringIO()
            json.dump(report_data, buffer, indent=4)
            buffer.seek(0)
            
            # Return the file
            return send_file(
                io.BytesIO(buffer.getvalue().encode()),
                mimetype='application/json',
                as_attachment=True,
                download_name=f"report_{report_id}_{datetime.now().strftime('%Y%m%d')}.json"
            )
        
        elif export_format == 'csv':
            # Export as CSV
            # Create a file-like object
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            
            # Write header
            writer.writerow(['Type', 'Severity', 'Location', 'Description', 'Remediation'])
            
            # Write vulnerability data
            for vuln in report.vulnerabilities:
                writer.writerow([
                    vuln.type,
                    vuln.severity,
                    vuln.location,
                    vuln.description,
                    vuln.remediation
                ])
            
            buffer.seek(0)
            
            # Return the file
            return send_file(
                io.BytesIO(buffer.getvalue().encode()),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f"report_{report_id}_{datetime.now().strftime('%Y%m%d')}.csv"
            )
        
        else:
            flash("Unsupported export format", "danger")
            return redirect(url_for('reports_bp.view_report', report_id=report_id))
    
    except Exception as e:
        logger.error(f"Error exporting report: {str(e)}")
        flash(f"Error exporting report: {str(e)}", "danger")
        return redirect(url_for('reports_bp.view_report', report_id=report_id))


@reports_bp.route('/report/<int:report_id>/delete', methods=['POST'])
def delete_report(report_id):
    """
    Route to delete a report
    """
    try:
        report = Report.query.get_or_404(report_id)
        
        # Delete vulnerabilities first
        Vulnerability.query.filter_by(report_id=report_id).delete()
        
        # Update related scans to remove report_id reference
        for scan in Scan.query.filter_by(report_id=report_id).all():
            scan.report_id = None
        
        # Delete the report
        db.session.delete(report)
        db.session.commit()
        
        flash("Report deleted successfully", "success")
        return redirect(url_for('reports_bp.list_reports'))
    
    except Exception as e:
        logger.error(f"Error deleting report: {str(e)}")
        flash(f"Error deleting report: {str(e)}", "danger")
        return redirect(url_for('reports_bp.view_report', report_id=report_id))
