import logging
import re
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class DataExposureScanner:
    """
    Module to detect exposed sensitive data and information leakage
    """
    
    def __init__(self, config):
        """
        Initialize data exposure scanner
        
        Args:
            config (dict): Scanner configuration
        """
        self.config = config
        self.timeout = config.get('timeout', 30)
        self.headers = {
            'User-Agent': config.get('user_agent', 'WebAppPenTestKit/1.0')
        }
        self.cookies = {}
        if config.get('cookies'):
            for cookie in config['cookies'].split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    self.cookies[name] = value
        
        # Patterns to detect sensitive data
        self.sensitive_patterns = [
            # Email addresses
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email Address', 'Low'),
            
            # API keys and tokens
            (r'api[_-]?key[_-]?[\w\d]{16,}', 'API Key', 'High'),
            (r'token[_-]?[\w\d]{16,}', 'Authentication Token', 'High'),
            (r'access[_-]?token[_-]?[\w\d]{16,}', 'Access Token', 'High'),
            (r'secret[_-]?key[_-]?[\w\d]{16,}', 'Secret Key', 'High'),
            
            # Password patterns in clear text
            (r'password\s*[=:]\s*[\'"]([^\'"]*)[\'""]', 'Hardcoded Password', 'Critical'),
            (r'passwd\s*[=:]\s*[\'"]([^\'"]*)[\'""]', 'Hardcoded Password', 'Critical'),
            (r'pwd\s*[=:]\s*[\'"]([^\'"]*)[\'""]', 'Hardcoded Password', 'Critical'),
            
            # AWS keys
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'Critical'),
            
            # Social Security Numbers (US)
            (r'\b\d{3}-\d{2}-\d{4}\b', 'Social Security Number', 'Critical'),
            
            # Credit card numbers
            (r'\b(?:\d[ -]*?){13,16}\b', 'Potential Credit Card Number', 'Critical'),
            
            # Internal IP addresses
            (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'Internal IP Address', 'Medium'),
            (r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b', 'Internal IP Address', 'Medium'),
            (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 'Internal IP Address', 'Medium'),
            
            # Database connection strings
            (r'(?i)connect.*?server.*?database', 'Database Connection String', 'High'),
            (r'(?i)jdbc:.*?://.*?/', 'JDBC Connection String', 'High'),
            
            # Private keys and certificates
            (r'-----BEGIN PRIVATE KEY-----', 'Private Key', 'Critical'),
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 'Critical'),
            (r'-----BEGIN CERTIFICATE-----', 'Certificate', 'Medium')
        ]
        
        # HTML comments to check for sensitive data
        self.html_comment_pattern = r'<!--(.*?)-->'
    
    def scan(self, urls):
        """
        Scan URLs for exposed sensitive data
        
        Args:
            urls (list): List of URLs to scan
            
        Returns:
            list: List of dictionaries containing vulnerability information
        """
        vulnerabilities = []
        
        for url in urls:
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=True
                )
                
                # Skip non-text responses
                content_type = response.headers.get('Content-Type', '').lower()
                if not any(ct in content_type for ct in ['text/html', 'text/plain', 'application/json', 'application/javascript', 'application/xml', 'text/xml']):
                    continue
                
                # Check for sensitive data in response
                found_data = self._find_sensitive_data(response.text)
                
                for data_type, matches, severity in found_data:
                    # Limit the number of matches to report (avoid excessive findings)
                    unique_matches = set(matches[:5])
                    
                    # Create redacted versions of matches for reporting
                    redacted_matches = []
                    for match in unique_matches:
                        # Redact middle portion of the sensitive data
                        if len(match) > 8:
                            redacted = match[:4] + '*' * (len(match) - 8) + match[-4:]
                        else:
                            redacted = '****' + match[-2:] if len(match) > 2 else match
                        redacted_matches.append(redacted)
                    
                    vulnerability = {
                        'type': 'Sensitive Data Exposure',
                        'severity': severity,
                        'location': url,
                        'data_type': data_type,
                        'description': f"Detected {data_type} in the response",
                        'proof': f"Found {len(unique_matches)} instance(s) of {data_type}: {', '.join(redacted_matches)}",
                        'remediation': 'Remove sensitive data from responses or implement proper data masking'
                    }
                    vulnerabilities.append(vulnerability)
                    logger.info(f"Found {data_type} in {url}")
                
                # Check for HTML comments
                if 'text/html' in content_type:
                    comment_vulnerabilities = self._check_html_comments(response.text, url)
                    vulnerabilities.extend(comment_vulnerabilities)
                
                # Check for excessive error information
                error_vulnerabilities = self._check_error_information(response.text, url)
                if error_vulnerabilities:
                    vulnerabilities.extend(error_vulnerabilities)
                
            except RequestException as e:
                logger.warning(f"Error requesting {url}: {str(e)}")
            except Exception as e:
                logger.error(f"Error processing {url}: {str(e)}")
        
        return vulnerabilities
    
    def _find_sensitive_data(self, content):
        """
        Find sensitive data in content
        
        Args:
            content (str): Response content
            
        Returns:
            list: List of tuples (data_type, matches, severity)
        """
        results = []
        
        for pattern, data_type, severity in self.sensitive_patterns:
            matches = re.findall(pattern, content)
            if matches:
                results.append((data_type, matches, severity))
        
        return results
    
    def _check_html_comments(self, content, url):
        """
        Check for sensitive information in HTML comments
        
        Args:
            content (str): HTML content
            url (str): URL being checked
            
        Returns:
            list: List of vulnerabilities related to HTML comments
        """
        vulnerabilities = []
        
        # Extract HTML comments
        comments = re.findall(self.html_comment_pattern, content)
        if not comments:
            return []
        
        # Check each comment for sensitive patterns
        suspicious_comments = []
        for comment in comments:
            comment = comment.strip()
            
            # Skip empty or very short comments
            if len(comment) < 5:
                continue
            
            # Check for sensitive keywords in comments
            sensitive_keywords = ['todo', 'fixme', 'hack', 'workaround', 'bug', 'debug', 'user', 'password', 'key', 'token', 'secret']
            
            for keyword in sensitive_keywords:
                if keyword in comment.lower():
                    if len(comment) > 100:
                        truncated_comment = comment[:97] + "..."
                    else:
                        truncated_comment = comment
                    suspicious_comments.append((keyword, truncated_comment))
                    break
        
        if suspicious_comments:
            examples = [f"'{keyword}': {comment[:30]}..." for keyword, comment in suspicious_comments[:3]]
            
            vulnerability = {
                'type': 'Sensitive Information in HTML Comments',
                'severity': 'Medium',
                'location': url,
                'description': 'HTML comments contain potentially sensitive information',
                'proof': f"Found {len(suspicious_comments)} suspicious comments. Examples: {'; '.join(examples)}",
                'remediation': 'Remove sensitive information from HTML comments in production code'
            }
            vulnerabilities.append(vulnerability)
            logger.info(f"Found sensitive HTML comments in {url}")
        
        return vulnerabilities
    
    def _check_error_information(self, content, url):
        """
        Check for excessive error information
        
        Args:
            content (str): Response content
            url (str): URL being checked
            
        Returns:
            list: List of vulnerabilities related to error disclosure
        """
        vulnerabilities = []
        
        # Check for common error patterns
        error_patterns = [
            (r'(?i)exception|stack trace|syntax error', 'Application Error Disclosure'),
            (r'(?i)sql (error|syntax)', 'SQL Error Disclosure'),
            (r'(?i)ORA-[0-9]{4,5}', 'Oracle DB Error Disclosure'),
            (r'(?i)mysql_error|mysql_fetch|mysql_num_rows', 'MySQL Error Disclosure'),
            (r'(?i)ODBC Driver|OLE DB Provider', 'ODBC/OLE DB Error Disclosure'),
            (r'(?i)Traceback \(most recent call last\)', 'Python Error Disclosure'),
            (r'(?i)Warning: .* on line [0-9]+', 'PHP Error Disclosure'),
            (r'(?i)Microsoft OLE DB Provider for SQL Server', 'MS SQL Error Disclosure'),
            (r'(?i)Error Executing Database Query', 'Database Error Disclosure'),
            (r'(?i)Fatal error:', 'PHP Fatal Error Disclosure')
        ]
        
        for pattern, error_type in error_patterns:
            matches = re.findall(pattern, content)
            if matches:
                vulnerability = {
                    'type': 'Error Information Disclosure',
                    'severity': 'Medium',
                    'location': url,
                    'description': f"{error_type} found in response",
                    'proof': f"Error pattern matched: {pattern}",
                    'remediation': 'Implement proper error handling to prevent disclosure of detailed error information'
                }
                vulnerabilities.append(vulnerability)
                logger.info(f"Found {error_type} in {url}")
                # Only report one error type per URL
                break
        
        return vulnerabilities
