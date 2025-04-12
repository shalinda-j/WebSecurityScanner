from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from modules.pqc_module import PQCryptographyModule
import logging
import json

logger = logging.getLogger(__name__)

pqc_bp = Blueprint('pqc_bp', __name__)

@pqc_bp.route('/pqc')
def pqc_dashboard():
    """
    Route for the PQC dashboard
    """
    # Create a PQC module instance
    pqc_module = PQCryptographyModule()
    
    # Get recommendations for implementing PQC
    recommendations = pqc_module.get_pqc_recommendations()
    
    # Get hybrid approach recommendation
    hybrid_recommendation = pqc_module.generate_hybrid_recommendation()
    
    return render_template(
        'pqc_dashboard.html',
        recommendations=recommendations,
        hybrid_recommendation=hybrid_recommendation
    )

@pqc_bp.route('/pqc/demo', methods=['GET', 'POST'])
def pqc_demo():
    """
    Route for demonstrating PQC algorithms
    """
    results = None
    
    if request.method == 'POST':
        try:
            # Create a PQC module instance
            pqc_module = PQCryptographyModule()
            
            # Run the demonstration
            results = pqc_module.demonstrate_pqc_algorithms()
            
            # Convert execution times to milliseconds and round for display
            for algo, data in results.items():
                if 'execution_time' in data:
                    data['execution_time_ms'] = round(data['execution_time'] * 1000, 2)
            
            flash("PQC algorithm demonstration completed successfully", "success")
        
        except Exception as e:
            logger.error(f"Error running PQC demo: {str(e)}")
            flash(f"Error running PQC demo: {str(e)}", "danger")
    
    return render_template('pqc_demo.html', results=results)

@pqc_bp.route('/pqc/compare')
def pqc_compare():
    """
    Route for comparing classical and post-quantum cryptography
    """
    # Data for comparison
    comparison_data = {
        'key_exchange': [
            {
                'algorithm': 'RSA-2048',
                'type': 'Classical',
                'security_level': 'Approx. 112 bits (classical)',
                'quantum_resistance': 'None',
                'key_size': '2048 bits',
                'performance': 'Fast',
                'standardization': 'Well-established'
            },
            {
                'algorithm': 'ECDH (P-256)',
                'type': 'Classical',
                'security_level': 'Approx. 128 bits (classical)',
                'quantum_resistance': 'None',
                'key_size': '256 bits',
                'performance': 'Very Fast',
                'standardization': 'Well-established'
            },
            {
                'algorithm': 'Kyber-768',
                'type': 'Post-Quantum',
                'security_level': 'NIST Level 3 (128 bits against quantum)',
                'quantum_resistance': 'Strong',
                'key_size': '1088 bytes (public), 2400 bytes (secret)',
                'performance': 'Moderate',
                'standardization': 'NIST Round 3 Selection'
            }
        ],
        'signatures': [
            {
                'algorithm': 'RSA-3072',
                'type': 'Classical',
                'security_level': 'Approx. 128 bits (classical)',
                'quantum_resistance': 'None',
                'signature_size': '384 bytes',
                'performance': 'Moderate',
                'standardization': 'Well-established'
            },
            {
                'algorithm': 'ECDSA (P-256)',
                'type': 'Classical',
                'security_level': 'Approx. 128 bits (classical)',
                'quantum_resistance': 'None',
                'signature_size': '64 bytes',
                'performance': 'Fast',
                'standardization': 'Well-established'
            },
            {
                'algorithm': 'Dilithium3',
                'type': 'Post-Quantum',
                'security_level': 'NIST Level 3 (128 bits against quantum)',
                'quantum_resistance': 'Strong',
                'signature_size': '2701 bytes',
                'performance': 'Moderate',
                'standardization': 'NIST Round 3 Selection'
            },
            {
                'algorithm': 'SPHINCS+-128f',
                'type': 'Post-Quantum',
                'security_level': 'NIST Level 1 (128 bits against quantum)',
                'quantum_resistance': 'Strong',
                'signature_size': '16976 bytes',
                'performance': 'Slow',
                'standardization': 'NIST Round 3 Selection'
            }
        ]
    }
    
    return render_template('pqc_compare.html', comparison_data=comparison_data)

@pqc_bp.route('/pqc/scan_form')
def pqc_scan_form():
    """
    Route for PQC-specific scanning form
    """
    return render_template('pqc_scan_form.html')