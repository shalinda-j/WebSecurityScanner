import logging
import urllib.parse
import re
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
from payloads.xss_payloads import XSS_PAYLOADS

logger = logging.getLogger(__name__)

class XSSScanner:
    """
    Scanner module to detect Cross-Site Scripting (XSS) vulnerabilities
    """
    
    def __init__(self, config):
        """
        Initialize XSS scanner
        
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
        Scan a list of URLs for XSS vulnerabilities
        
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
            
            # Test each parameter for XSS
            for param_name in parameters:
                logger.debug(f"Testing parameter {param_name} in {url} for XSS")
                
                # Test the parameter with each payload
                for payload in XSS_PAYLOADS:
                    test_url = self._create_test_url(url, param_name, payload)
                    
                    try:
                        # Send the request
                        response = requests.get(
                            test_url,
                            headers=self.headers,
                            cookies=self.cookies,
                            timeout=self.timeout,
                            verify=True
                        )
                        
                        # Check if the payload is reflected in the response
                        if self._check_xss_reflection(response.text, payload):
                            vulnerability = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'High',
                                'location': url,
                                'parameter': param_name,
                                'payload': payload,
                                'description': f"XSS vulnerability found in parameter '{param_name}'",
                                'proof': f"Parameter '{param_name}' with payload '{payload}' was reflected in the response",
                                'remediation': (
                                    "1. Implement proper input validation\n"
                                    "2. Use HTML entity encoding for user input\n"
                                    "3. Implement Content Security Policy (CSP)\n"
                                    "4. Use modern frameworks with built-in XSS protection\n"
                                    "5. Validate input on both client and server sides"
                                )
                            }
                            vulnerabilities.append(vulnerability)
                            logger.info(f"Found XSS in {url}, parameter: {param_name}")
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
        Create a test URL with the XSS payload
        
        Args:
            url (str): Original URL
            param_name (str): Parameter name to inject
            payload (str): XSS payload
            
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
    
    def _check_xss_reflection(self, response_text, payload):
        """
        Check if the XSS payload is reflected in the response
        
        Args:
            response_text (str): HTTP response text
            payload (str): XSS payload to check for
            
        Returns:
            bool: True if payload is reflected, False otherwise
        """
        # Simple check for exact payload reflection
        if payload in response_text:
            # Parse the HTML to check context
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check if the payload appears in a potentially exploitable context
            # - Inside script tags
            for script_tag in soup.find_all('script'):
                if payload in script_tag.string:
                    return True
            
            # - As attribute values
            for tag in soup.find_all(True):
                for attr_name, attr_value in tag.attrs.items():
                    if isinstance(attr_value, str) and payload in attr_value:
                        return True
            
            # - In HTML content directly
            text_nodes = soup.find_all(string=re.compile(re.escape(payload)))
            if text_nodes:
                return True
        
        # Additional checks for encoded versions
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in response_text:
            # This suggests HTML encoding is happening, which may prevent XSS
            # But we should check if the context allows for bypass
            return False
        
        return False
