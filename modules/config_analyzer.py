import logging
import re
import requests
from requests.exceptions import RequestException
import urllib.parse
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class ConfigAnalyzer:
    """
    Module to detect server misconfigurations and security issues
    """
    
    def __init__(self, config):
        """
        Initialize configuration analyzer
        
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
        
        # URLs to check for common security misconfigurations
        self.sensitive_paths = [
            '/.git/',
            '/.env',
            '/.htaccess',
            '/config.php',
            '/wp-config.php',
            '/config.js',
            '/config.json',
            '/robots.txt',
            '/sitemap.xml',
            '/server-status',
            '/phpinfo.php',
            '/admin/',
            '/backup/',
            '/db/',
            '/logs/',
            '/test.php',
            '/phpMyAdmin/',
            '/adminer.php',
            '/composer.json',
            '/package.json',
            '/node_modules/',
            '/vendor/',
            '/.svn/',
            '/.hg/',
            '/database.yml',
            '/config.yml',
            '/credentials.json',
            '/keys.js'
        ]
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing Content Security Policy',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Referrer-Policy': 'Missing Referrer-Policy header',
            'Feature-Policy': 'Missing Feature-Policy/Permissions-Policy header',
            'Permissions-Policy': 'Missing Permissions-Policy header'
        }
    
    def scan(self, urls):
        """
        Scan for server misconfigurations
        
        Args:
            urls (list): List of URLs (not heavily used for this module)
            
        Returns:
            list: List of dictionaries containing vulnerability information
        """
        vulnerabilities = []
        
        # Main URL and base domain
        main_url = self.config['url']
        base_url = self._get_base_url(main_url)
        
        # Check for missing security headers
        header_vulnerabilities = self._check_security_headers(main_url)
        vulnerabilities.extend(header_vulnerabilities)
        
        # Check for sensitive files and directory listing
        sensitive_file_vulnerabilities = self._check_sensitive_files(base_url)
        vulnerabilities.extend(sensitive_file_vulnerabilities)
        
        # Check for SSL/TLS issues
        if main_url.startswith('https://'):
            ssl_vulnerabilities = self._check_ssl_issues(main_url)
            vulnerabilities.extend(ssl_vulnerabilities)
        else:
            # HTTP site (not HTTPS)
            vulnerabilities.append({
                'type': 'Insecure Communication',
                'severity': 'High',
                'location': main_url,
                'description': 'Website is using HTTP instead of HTTPS',
                'proof': 'URL begins with http://',
                'remediation': 'Implement HTTPS with a valid SSL certificate and redirect all HTTP traffic to HTTPS'
            })
        
        # Check for cookies without secure flag
        cookie_vulnerabilities = self._check_cookie_security(main_url)
        vulnerabilities.extend(cookie_vulnerabilities)
        
        return vulnerabilities
    
    def _get_base_url(self, url):
        """
        Get the base URL (scheme + domain) from a full URL
        
        Args:
            url (str): Full URL
            
        Returns:
            str: Base URL
        """
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _check_security_headers(self, url):
        """
        Check for missing security headers
        
        Args:
            url (str): URL to check
            
        Returns:
            list: List of vulnerabilities related to security headers
        """
        vulnerabilities = []
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                verify=True
            )
            
            # Check for missing security headers
            for header, description in self.security_headers.items():
                if header not in response.headers:
                    severity = 'Medium' if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else 'Low'
                    
                    vulnerability = {
                        'type': 'Missing Security Header',
                        'severity': severity,
                        'location': url,
                        'header': header,
                        'description': description,
                        'proof': 'Header not present in HTTP response',
                        'remediation': f"Implement the {header} security header according to best practices"
                    }
                    vulnerabilities.append(vulnerability)
                    logger.info(f"Missing security header: {header}")
            
        except RequestException as e:
            logger.warning(f"Error requesting {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing {url}: {str(e)}")
        
        return vulnerabilities
    
    def _check_sensitive_files(self, base_url):
        """
        Check for sensitive files and directory listing
        
        Args:
            base_url (str): Base URL
            
        Returns:
            list: List of vulnerabilities related to sensitive files and directory listing
        """
        vulnerabilities = []
        
        for path in self.sensitive_paths:
            url = f"{base_url}{path}"
            
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    cookies=self.cookies,
                    timeout=self.timeout,
                    verify=True,
                    allow_redirects=False  # Don't follow redirects
                )
                
                # Check if the resource exists (2xx response)
                if 200 <= response.status_code < 300:
                    # Check for directory listing
                    is_directory_listing = self._is_directory_listing(response)
                    
                    if is_directory_listing:
                        vulnerability = {
                            'type': 'Directory Listing Enabled',
                            'severity': 'Medium',
                            'location': url,
                            'description': 'Directory listing is enabled, exposing file structure',
                            'proof': 'Directory listing page detected',
                            'remediation': 'Disable directory listing in web server configuration'
                        }
                        vulnerabilities.append(vulnerability)
                        logger.info(f"Directory listing enabled: {url}")
                    else:
                        # Sensitive file found
                        vulnerability = {
                            'type': 'Sensitive File Exposure',
                            'severity': 'High',
                            'location': url,
                            'description': f"Sensitive file or directory exposed: {path}",
                            'proof': f"Resource accessible with status code {response.status_code}",
                            'remediation': 'Restrict access to sensitive files or remove them from web root'
                        }
                        vulnerabilities.append(vulnerability)
                        logger.info(f"Sensitive file exposed: {url}")
            
            except RequestException as e:
                logger.debug(f"Error requesting {url}: {str(e)}")
            except Exception as e:
                logger.error(f"Error processing {url}: {str(e)}")
        
        return vulnerabilities
    
    def _is_directory_listing(self, response):
        """
        Check if the response indicates a directory listing
        
        Args:
            response (Response): HTTP response object
            
        Returns:
            bool: True if directory listing is detected, False otherwise
        """
        # Check for common directory listing indicators
        indicators = [
            'Index of /',
            '<title>Index of',
            'Directory Listing For',
            'Parent Directory</a>'
        ]
        
        for indicator in indicators:
            if indicator in response.text:
                return True
        
        # Check for HTML tables with file listings
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for table structure common in directory listings
            tables = soup.find_all('table')
            for table in tables:
                headers = [th.text.strip().lower() for th in table.find_all('th')]
                if headers and any(h in ' '.join(headers) for h in ['name', 'size', 'modified', 'description']):
                    # Likely a directory listing table
                    return True
        except Exception:
            pass
        
        return False
    
    def _check_ssl_issues(self, url):
        """
        Check for SSL/TLS issues
        Note: Limited capability in this implementation
        
        Args:
            url (str): URL to check
            
        Returns:
            list: List of vulnerabilities related to SSL/TLS
        """
        vulnerabilities = []
        
        try:
            # Request with specific SSL/TLS options
            response = requests.get(
                url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                verify=True
            )
            
            # We can't do comprehensive SSL testing without specialized libraries
            # This is a simplified check based on response headers
            
            # Check for HSTS with short max-age
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            if hsts_header:
                max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age < 15768000:  # Less than 6 months
                        vulnerability = {
                            'type': 'Weak HSTS Configuration',
                            'severity': 'Low',
                            'location': url,
                            'description': 'HSTS max-age is too short (less than 6 months)',
                            'proof': f"HSTS header: {hsts_header}",
                            'remediation': 'Set HSTS max-age to at least 15768000 seconds (6 months)'
                        }
                        vulnerabilities.append(vulnerability)
            
        except RequestException as e:
            logger.warning(f"Error requesting {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing {url}: {str(e)}")
        
        return vulnerabilities
    
    def _check_cookie_security(self, url):
        """
        Check for cookies without secure flag or with other security issues
        
        Args:
            url (str): URL to check
            
        Returns:
            list: List of vulnerabilities related to cookies
        """
        vulnerabilities = []
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                verify=True
            )
            
            # Check cookies from response
            for cookie in response.cookies:
                cookie_issues = []
                
                # Check for Secure flag
                if not cookie.secure and url.startswith('https://'):
                    cookie_issues.append('Missing Secure flag')
                
                # Check for HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    cookie_issues.append('Missing HttpOnly flag')
                
                # Check for SameSite attribute
                if not cookie.has_nonstandard_attr('SameSite'):
                    cookie_issues.append('Missing SameSite attribute')
                
                # Check for Expires/Max-Age attributes
                if cookie.expires is None and not cookie.has_nonstandard_attr('Max-Age'):
                    cookie_issues.append('Missing Expires/Max-Age attributes (session cookie)')
                
                if cookie_issues:
                    vulnerability = {
                        'type': 'Insecure Cookie Configuration',
                        'severity': 'Medium',
                        'location': url,
                        'cookie': cookie.name,
                        'description': f"Cookie '{cookie.name}' has security issues: {', '.join(cookie_issues)}",
                        'proof': f"Cookie issues: {', '.join(cookie_issues)}",
                        'remediation': 'Implement proper cookie security attributes (Secure, HttpOnly, SameSite)'
                    }
                    vulnerabilities.append(vulnerability)
                    logger.info(f"Insecure cookie found: {cookie.name}")
            
        except RequestException as e:
            logger.warning(f"Error requesting {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing {url}: {str(e)}")
        
        return vulnerabilities
