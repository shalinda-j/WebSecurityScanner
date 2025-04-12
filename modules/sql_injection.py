import logging
import re
import urllib.parse
import requests
from requests.exceptions import RequestException
from payloads.sql_payloads import SQL_PAYLOADS, SQL_ERROR_PATTERNS

logger = logging.getLogger(__name__)

class SQLInjectionScanner:
    """
    Scanner module to detect SQL injection vulnerabilities
    """
    
    def __init__(self, config):
        """
        Initialize SQL injection scanner
        
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
    
    def scan(self, urls):
        """
        Scan a list of URLs for SQL injection vulnerabilities
        
        Args:
            urls (list): List of URLs to scan
            
        Returns:
            list: List of dictionaries containing vulnerability information
        """
        vulnerabilities = []
        
        for url in urls:
            # Only test URLs with parameters
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.query:
                continue
            
            # Get parameters from URL
            parameters = self._get_parameters(parsed_url.query)
            
            # Test each parameter for SQL injection
            for param_name in parameters:
                logger.debug(f"Testing parameter {param_name} in {url}")
                
                # Test the parameter with each payload
                for payload in SQL_PAYLOADS:
                    test_url = self._create_test_url(url, param_name, payload)
                    
                    try:
                        # Send the request
                        response = requests.get(
                            test_url,
                            headers=self.headers,
                            cookies=self.cookies,
                            timeout=self.timeout,
                            verify=True,
                            allow_redirects=False
                        )
                        
                        # Check for SQL errors in the response
                        if self._check_sql_error(response.text):
                            vulnerability = {
                                'type': 'SQL Injection',
                                'severity': 'High',
                                'location': url,
                                'parameter': param_name,
                                'payload': payload,
                                'description': f"SQL Injection vulnerability found in parameter '{param_name}'",
                                'proof': f"Parameter '{param_name}' with payload '{payload}' triggered SQL error",
                                'remediation': (
                                    "1. Use parameterized queries or prepared statements\n"
                                    "2. Apply input validation and sanitization\n"
                                    "3. Use an ORM or database abstraction layer\n"
                                    "4. Implement least privilege database accounts\n"
                                    "5. Consider using stored procedures"
                                )
                            }
                            vulnerabilities.append(vulnerability)
                            logger.info(f"Found SQL Injection in {url}, parameter: {param_name}")
                            # Skip remaining payloads for this parameter
                            break
                        
                    except RequestException as e:
                        logger.warning(f"Error testing {test_url}: {str(e)}")
                    except Exception as e:
                        logger.error(f"Unexpected error testing {test_url}: {str(e)}")
        
        return vulnerabilities
    
    def _get_parameters(self, query_string):
        """
        Extract parameters from a query string
        
        Args:
            query_string (str): URL query string
            
        Returns:
            dict: Dictionary of parameter names and values
        """
        parameters = {}
        for param in query_string.split('&'):
            if '=' in param:
                name, value = param.split('=', 1)
                parameters[name] = value
        return parameters
    
    def _create_test_url(self, url, param_name, payload):
        """
        Create a test URL with the SQL injection payload
        
        Args:
            url (str): Original URL
            param_name (str): Parameter name to inject
            payload (str): SQL injection payload
            
        Returns:
            str: URL with injected payload
        """
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Replace the parameter value with the payload
        query_params[param_name] = [payload]
        
        # Rebuild the query string
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        
        # Rebuild the URL
        new_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        return new_url
    
    def _check_sql_error(self, response_text):
        """
        Check if the response contains SQL error messages
        
        Args:
            response_text (str): HTTP response text
            
        Returns:
            bool: True if SQL error is detected, False otherwise
        """
        for pattern in SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False
