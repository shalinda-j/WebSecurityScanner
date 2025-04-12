"""
Validation functions for the Web Application Penetration Testing Toolkit
"""
import re
import ipaddress
import urllib.parse
import logging

logger = logging.getLogger(__name__)

def is_valid_url(url):
    """
    Validate if a string is a valid URL
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid URL, False otherwise
    """
    if not url:
        return False
    
    try:
        # Check for scheme
        parsed_url = urllib.parse.urlparse(url)
        
        # URL must have a scheme (http or https) and netloc
        if not parsed_url.scheme or not parsed_url.netloc:
            return False
        
        # Scheme must be http or https for web applications
        if parsed_url.scheme not in ('http', 'https'):
            return False
        
        # Additional checks can be added here as needed
        
        return True
    
    except Exception as e:
        logger.error(f"Error validating URL: {str(e)}")
        return False


def is_valid_ip(ip_str):
    """
    Validate if a string is a valid IP address (IPv4 or IPv6)
    
    Args:
        ip_str (str): IP address to validate
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_domain(domain):
    """
    Validate if a string is a valid domain name
    
    Args:
        domain (str): Domain to validate
        
    Returns:
        bool: True if valid domain, False otherwise
    """
    # Simple domain regex (more complex validation may be needed for IDNs)
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, domain))


def is_valid_email(email):
    """
    Validate if a string is a valid email address
    
    Args:
        email (str): Email to validate
        
    Returns:
        bool: True if valid email, False otherwise
    """
    # Basic email regex (simplified for clarity)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))


def is_valid_port(port):
    """
    Validate if a value is a valid port number
    
    Args:
        port: Port number to validate (int or string)
        
    Returns:
        bool: True if valid port, False otherwise
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_safe_path(path):
    """
    Check if a file path is safe (no path traversal)
    
    Args:
        path (str): File path to check
        
    Returns:
        bool: True if safe, False otherwise
    """
    # Check for common path traversal patterns
    if '..' in path or '//' in path or '\\\\' in path:
        return False
    
    # Check for absolute paths
    if path.startswith('/') or path.startswith('\\'):
        return False
    
    # Additional checks can be added here as needed
    
    return True


def is_valid_scan_module(module_name):
    """
    Check if a module name is valid for scanning
    
    Args:
        module_name (str): Module name to check
        
    Returns:
        bool: True if valid module, False otherwise
    """
    # List of valid scanning modules
    valid_modules = ['sql', 'xss', 'version', 'config', 'exposure', 'pqc']
    
    return module_name in valid_modules


def validate_scan_config(config):
    """
    Validate scan configuration
    
    Args:
        config (dict): Scan configuration
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not config:
        return False, "Configuration cannot be empty"
    
    # Check required fields
    if 'url' not in config:
        return False, "Target URL is required"
    
    if not is_valid_url(config['url']):
        return False, "Invalid target URL"
    
    # Validate optional fields
    if 'depth' in config:
        try:
            depth = int(config['depth'])
            if depth < 1 or depth > 10:
                return False, "Crawl depth must be between 1 and 10"
        except (ValueError, TypeError):
            return False, "Invalid crawl depth"
    
    if 'timeout' in config:
        try:
            timeout = int(config['timeout'])
            if timeout < 1 or timeout > 300:
                return False, "Timeout must be between 1 and 300 seconds"
        except (ValueError, TypeError):
            return False, "Invalid timeout value"
    
    # Additional validations can be added here
    
    return True, ""


def is_safe_user_input(input_str):
    """
    Check if user input is safe for display (basic XSS prevention)
    
    Args:
        input_str (str): Input to check
        
    Returns:
        bool: True if safe, False otherwise
    """
    # Check for script tags and event handlers
    dangerous_patterns = [
        r'<script',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe',
        r'<object',
        r'<embed',
        r'<form',
        r'<img[^>]+\bonerror\b'
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            return False
    
    return True
