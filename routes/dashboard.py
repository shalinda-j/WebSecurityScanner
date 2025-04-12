from flask import Blueprint, render_template, redirect, url_for, flash
from models import Scan, Report, Vulnerability
from app import db
from collections import Counter
import logging

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint('dashboard_bp', __name__)

@dashboard_bp.route('/')
def index():
    """
    Route for the main dashboard page
    """
    try:
        # Get recent scans (last 5)
        recent_scans = Scan.query.order_by(Scan.scan_date.desc()).limit(5).all()
        
        # Get recent reports (last 5)
        recent_reports = Report.query.order_by(Report.created_at.desc()).limit(5).all()
        
        # Gather statistics for dashboard
        stats = {}
        total_scans = Scan.query.count()
        total_vulnerabilities = Vulnerability.query.count()
        
        # Only continue if we have data
        if total_vulnerabilities > 0:
            # Count vulnerabilities by severity
            vulnerability_counts = {
                'Critical': Vulnerability.query.filter_by(severity='Critical').count(),
                'High': Vulnerability.query.filter_by(severity='High').count(),
                'Medium': Vulnerability.query.filter_by(severity='Medium').count(),
                'Low': Vulnerability.query.filter_by(severity='Low').count(),
                'Info': Vulnerability.query.filter_by(severity='Info').count()
            }
            
            # Find most common issue type
            vuln_types = [v.type for v in Vulnerability.query.all()]
            most_common = Counter(vuln_types).most_common(1)
            most_common_issue = most_common[0][0] if most_common else "None"
            
            stats = {
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulnerabilities,
                'vulnerability_counts': vulnerability_counts,
                'most_common_issue': most_common_issue
            }
            
        return render_template('index.html', 
                              recent_scans=recent_scans, 
                              recent_reports=recent_reports,
                              stats=stats)
    
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return render_template('index.html', recent_scans=[], recent_reports=[], stats=None)


@dashboard_bp.route('/about')
def about():
    """
    Route for the about page
    """
    return render_template('about.html')
