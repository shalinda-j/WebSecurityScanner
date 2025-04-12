"""
Helper functions for the Web Application Penetration Testing Toolkit
"""
import logging
import re
import json
import urllib.parse
from datetime import datetime

logger = logging.getLogger(__name__)

def calculate_risk_score(vulnerability_counts):
    """
    Calculate risk score based on vulnerability counts by severity
    
    Args:
        vulnerability_counts (dict): Dictionary with counts by severity
        
    Returns:
        tuple: (risk_score, risk_level)
    """
    # Weights for each severity level
    weights = {
        'Critical': 10,
        'High': 5,
        'Medium': 2,
        'Low': 0.5,
        'Info': 0
    }
    
    # Calculate weighted score
    risk_score = sum(vulnerability_counts.get(severity, 0) * weight 
                    for severity, weight in weights.items())
    
    # Determine risk level
    if risk_score >= 20:
        risk_level = "Critical"
    elif risk_score >= 10:
        risk_level = "High"
    elif risk_score >= 5:
        risk_level = "Medium"
    elif risk_score > 0:
        risk_level = "Low"
    else:
        risk_level = "Informational"
    
    return risk_score, risk_level


def format_timestamp(timestamp, format_str='%Y-%m-%d %H:%M:%S'):
    """
    Format a timestamp into a readable string
    
    Args:
        timestamp: Timestamp to format (datetime object or ISO string)
        format_str: Format string
        
    Returns:
        str: Formatted timestamp
    """
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except ValueError:
            try:
                timestamp = datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                return timestamp
    
    if isinstance(timestamp, datetime):
        return timestamp.strftime(format_str)
    
    return str(timestamp)


def sanitize_html(text):
    """
    Sanitize HTML input
    
    Args:
        text (str): Text that might contain HTML
        
    Returns:
        str: Sanitized text
    """
    if not text:
        return ""
    
    # Replace potentially dangerous characters
    sanitized = text.replace("<", "&lt;").replace(">", "&gt;")
    return sanitized


def get_domain_from_url(url):
    """
    Extract domain from URL
    
    Args:
        url (str): URL to parse
        
    Returns:
        str: Domain name
    """
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        return domain
    except Exception as e:
        logger.error(f"Error extracting domain from URL: {str(e)}")
        return url


def truncate_string(text, max_length=100, suffix='...'):
    """
    Truncate a string to a maximum length
    
    Args:
        text (str): String to truncate
        max_length (int): Maximum length
        suffix (str): Suffix to add if truncated
        
    Returns:
        str: Truncated string
    """
    if not text:
        return ""
    
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def is_valid_json(json_string):
    """
    Check if a string is valid JSON
    
    Args:
        json_string (str): String to check
        
    Returns:
        bool: True if valid JSON, False otherwise
    """
    try:
        json.loads(json_string)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_regex(regex_string):
    """
    Check if a string is a valid regex pattern
    
    Args:
        regex_string (str): Regex pattern to check
        
    Returns:
        bool: True if valid regex, False otherwise
    """
    try:
        re.compile(regex_string)
        return True
    except re.error:
        return False


def escape_markdown(text):
    """
    Escape markdown special characters
    
    Args:
        text (str): Text to escape
        
    Returns:
        str: Escaped text for markdown
    """
    if not text:
        return ""
    
    # Characters to escape: \ ` * _ { } [ ] ( ) # + - . !
    markdown_chars = ['\\', '`', '*', '_', '{', '}', '[', ']', '(', ')', '#', '+', '-', '.', '!']
    
    for char in markdown_chars:
        text = text.replace(char, '\\' + char)
    
    return text


def format_bytes(bytes_value, precision=2):
    """
    Format bytes to human-readable size
    
    Args:
        bytes_value (int): Size in bytes
        precision (int): Decimal precision
        
    Returns:
        str: Formatted size string
    """
    if bytes_value < 0:
        return "0 B"
    
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    suffix_index = 0
    
    while bytes_value >= 1024 and suffix_index < len(suffixes) - 1:
        bytes_value /= 1024
        suffix_index += 1
    
    return f"{bytes_value:.{precision}f} {suffixes[suffix_index]}"


def get_severity_color(severity):
    """
    Get appropriate CSS color class for a severity level
    
    Args:
        severity (str): Severity level
        
    Returns:
        str: CSS color class
    """
    severity_colors = {
        'Critical': 'danger',
        'High': 'warning',
        'Medium': 'info',
        'Low': 'success',
        'Info': 'secondary'
    }
    
    return severity_colors.get(severity, 'secondary')
