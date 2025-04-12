import os
import logging
from app import app
from routes.dashboard import dashboard_bp
from routes.scan import scan_bp
from routes.reports import reports_bp
from routes.pqc import pqc_bp
from routes.apt import apt_bp

# Setup logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Register blueprints
app.register_blueprint(dashboard_bp)
app.register_blueprint(scan_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(pqc_bp)
app.register_blueprint(apt_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
