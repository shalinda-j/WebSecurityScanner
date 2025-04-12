import logging
import re
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class VersionDetector:
    """
    Module to detect software versions and potential vulnerabilities based on outdated software
    """
    
    def __init__(self, config):
        """
        Initialize version detector
        
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
        
        # Common software version patterns in headers, HTML, and JavaScript
        self.version_patterns = {
            'Apache': [
                r'Apache/(\d+\.\d+\.\d+)',
                r'Apache Server at'
            ],
            'Nginx': [
                r'nginx/(\d+\.\d+\.\d+)',
                r'<center>nginx</center>'
            ],
            'PHP': [
                r'X-Powered-By: PHP/(\d+\.\d+\.\d+)',
                r'PHP/(\d+\.\d+\.\d+)',
                r'<meta name="generator" content="PHP (\d+\.\d+\.\d+)"'
            ],
            'WordPress': [
                r'<meta name="generator" content="WordPress (\d+\.\d+\.\d+)"',
                r'/wp-content/',
                r'/wp-includes/'
            ],
            'Joomla': [
                r'<meta name="generator" content="Joomla! (\d+\.\d+\.\d+)"',
                r'/media/jui/'
            ],
            'Drupal': [
                r'<meta name="Generator" content="Drupal (\d+)"',
                r'jQuery.extend\(Drupal\.settings'
            ],
            'jQuery': [
                r'jquery[.-](\d+\.\d+\.\d+)\.js',
                r'jQuery v(\d+\.\d+\.\d+)'
            ],
            'Bootstrap': [
                r'bootstrap[.-](\d+\.\d+\.\d+)\.css',
                r'bootstrap[.-](\d+\.\d+\.\d+)\.js'
            ],
            'ASP.NET': [
                r'X-AspNet-Version: (\d+\.\d+\.\d+)',
                r'__VIEWSTATE'
            ],
            'IIS': [
                r'Server: Microsoft-IIS/(\d+\.\d+)',
                r'X-Powered-By: ASP.NET'
            ],
            'OpenSSL': [
                r'OpenSSL/(\d+\.\d+\.\d+)'
            ],
            'Tomcat': [
                r'Apache Tomcat/(\d+\.\d+\.\d+)',
                r'Tomcat'
            ],
            'Node.js': [
                r'Node/(\d+\.\d+\.\d+)'
            ]
        }
        
        # Known vulnerable versions (simplified for this example)
        self.vulnerable_versions = {
            'Apache': {
                '2.4.49': {
                    'severity': 'Critical',
                    'cves': ['CVE-2021-41773', 'CVE-2021-42013'],
                    'description': 'Path traversal vulnerability'
                },
                '2.4.50': {
                    'severity': 'Critical',
                    'cves': ['CVE-2021-42013'],
                    'description': 'Path traversal vulnerability'
                }
            },
            'Nginx': {
                '1.20.0': {
                    'severity': 'High',
                    'cves': ['CVE-2021-23017'],
                    'description': 'Memory corruption vulnerability'
                }
            },
            'PHP': {
                '7.4.11': {
                    'severity': 'High',
                    'cves': ['CVE-2020-7070'],
                    'description': 'Remote code execution vulnerability'
                },
                '5.6.40': {
                    'severity': 'Critical',
                    'cves': ['Multiple'],
                    'description': 'PHP 5.x is end-of-life and has multiple vulnerabilities'
                }
            },
            'WordPress': {
                '5.8.1': {
                    'severity': 'High',
                    'cves': ['CVE-2021-39200', 'CVE-2021-39201'],
                    'description': 'Cross-site scripting vulnerability'
                }
            }
        }
    
    def scan(self, urls):
        """
        Scan URLs to detect software versions
        
        Args:
            urls (list): List of URLs to scan
            
        Returns:
            list: List of dictionaries containing vulnerability information
        """
        vulnerabilities = []
        
        # We'll focus on the main URL for version detection
        main_url = self.config['url']
        
        try:
            response = requests.get(
                main_url,
                headers=self.headers,
                cookies=self.cookies,
                timeout=self.timeout,
                verify=True
            )
            
            # Check response headers and body for software versions
            detected_software = self._detect_versions(response)
            
            # Check for vulnerable versions
            for software, version in detected_software.items():
                if software in self.vulnerable_versions and version in self.vulnerable_versions[software]:
                    vuln_info = self.vulnerable_versions[software][version]
                    
                    vulnerability = {
                        'type': f'Outdated Software: {software}',
                        'severity': vuln_info['severity'],
                        'location': main_url,
                        'software': software,
                        'version': version,
                        'cves': ', '.join(vuln_info['cves']),
                        'description': f"{software} version {version} is vulnerable: {vuln_info['description']}",
                        'proof': f"Detected {software} version {version} in HTTP response",
                        'remediation': f"Update {software} to the latest stable version to patch known vulnerabilities"
                    }
                    vulnerabilities.append(vulnerability)
                    logger.info(f"Found vulnerable {software} version {version}")
                
                # Even if not in vulnerable_versions, report old software
                else:
                    # Add as informational finding
                    vulnerability = {
                        'type': f'Software Version Disclosure: {software}',
                        'severity': 'Info',
                        'location': main_url,
                        'software': software,
                        'version': version,
                        'description': f"Detected {software} version {version}",
                        'proof': f"Found version information in HTTP response",
                        'remediation': "Remove or hide version information in HTTP headers and HTML source code"
                    }
                    vulnerabilities.append(vulnerability)
                    logger.debug(f"Found {software} version {version}")
                    
        except RequestException as e:
            logger.warning(f"Error requesting {main_url}: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing {main_url}: {str(e)}")
        
        return vulnerabilities
    
    def _detect_versions(self, response):
        """
        Detect software versions from HTTP response
        
        Args:
            response (Response): HTTP response object
            
        Returns:
            dict: Detected software and versions
        """
        detected = {}
        
        # Check HTTP headers
        for header, value in response.headers.items():
            # Server header often contains web server version
            if header.lower() == 'server':
                for software, patterns in self.version_patterns.items():
                    for pattern in patterns:
                        match = re.search(pattern, value)
                        if match and len(match.groups()) > 0:
                            detected[software] = match.group(1)
                        elif match:
                            detected[software] = 'Unknown version'
            
            # X-Powered-By header often reveals backend technology
            if header.lower() == 'x-powered-by':
                for software, patterns in self.version_patterns.items():
                    for pattern in patterns:
                        match = re.search(pattern, value)
                        if match and len(match.groups()) > 0:
                            detected[software] = match.group(1)
                        elif match:
                            detected[software] = 'Unknown version'
        
        # Check response body
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check meta tags
            for meta in soup.find_all('meta'):
                content = meta.get('content', '')
                name = meta.get('name', '')
                
                if name.lower() == 'generator':
                    for software, patterns in self.version_patterns.items():
                        for pattern in patterns:
                            match = re.search(pattern, content)
                            if match and len(match.groups()) > 0:
                                detected[software] = match.group(1)
                            elif match:
                                detected[software] = 'Unknown version'
            
            # Check script tags for JavaScript libraries
            for script in soup.find_all('script'):
                src = script.get('src', '')
                for software, patterns in self.version_patterns.items():
                    for pattern in patterns:
                        match = re.search(pattern, src)
                        if match and len(match.groups()) > 0:
                            detected[software] = match.group(1)
                
                # Check inline script content
                if script.string:
                    for software, patterns in self.version_patterns.items():
                        for pattern in patterns:
                            match = re.search(pattern, script.string)
                            if match and len(match.groups()) > 0:
                                detected[software] = match.group(1)
            
            # Check entire HTML content
            for software, patterns in self.version_patterns.items():
                for pattern in patterns:
                    match = re.search(pattern, response.text)
                    if match and len(match.groups()) > 0:
                        detected[software] = match.group(1)
                    elif match and software not in detected:
                        detected[software] = 'Unknown version'
                        
        except Exception as e:
            logger.error(f"Error parsing HTML for version detection: {str(e)}")
        
        return detected
