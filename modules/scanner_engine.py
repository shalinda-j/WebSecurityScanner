import logging
import time
import concurrent.futures
import urllib.parse
import requests
from requests.exceptions import RequestException
from .sql_injection import SQLInjectionScanner
from .xss_scanner import XSSScanner
from .version_detector import VersionDetector
from .config_analyzer import ConfigAnalyzer
from .data_exposure import DataExposureScanner

logger = logging.getLogger(__name__)

class ScannerEngine:
    """
    Core scanning engine that coordinates and runs various vulnerability scanning modules
    """
    
    def __init__(self, config):
        """
        Initialize the scanner engine with configuration
        
        Args:
            config (dict): Configuration dictionary containing scan parameters
                - url: Target URL
                - depth: Crawling depth
                - timeout: Request timeout
                - user_agent: Custom User-Agent
                - cookies: Cookies to include with requests
        """
        self.config = config
        self.base_url = self.config['url']
        self.timeout = self.config.get('timeout', 30)
        self.depth = self.config.get('depth', 2)
        self.visited_urls = set()
        self.to_visit = [self.base_url]
        self.found_urls = []
        self.headers = {
            'User-Agent': config.get('user_agent', 'WebAppPenTestKit/1.0')
        }
        
        # Initialize cookies if provided
        self.cookies = {}
        if config.get('cookies'):
            for cookie in config['cookies'].split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    self.cookies[name] = value
    
    def run_scan(self, modules):
        """
        Run the scan with specified modules
        
        Args:
            modules (list): List of module names to run
            
        Returns:
            dict: Results from all modules
        """
        # First, crawl the site to discover URLs
        self.crawl()
        
        # Initialize module results dictionary
        results = {}
        
        # Map module names to their classes
        module_map = {
            'sql': SQLInjectionScanner,
            'xss': XSSScanner,
            'version': VersionDetector,
            'config': ConfigAnalyzer,
            'exposure': DataExposureScanner
        }
        
        # Run each requested module
        for module_name in modules:
            if module_name in module_map:
                logger.info(f"Running module: {module_name}")
                try:
                    module_instance = module_map[module_name](self.config)
                    module_results = module_instance.scan(self.found_urls)
                    results[module_name] = module_results
                    logger.info(f"Module {module_name} completed, found {len(module_results)} issues")
                except Exception as e:
                    logger.error(f"Error running module {module_name}: {str(e)}")
                    results[module_name] = []
            else:
                logger.warning(f"Unknown module: {module_name}")
        
        return results
    
    def crawl(self):
        """
        Crawl the target site to discover URLs for scanning
        """
        logger.info(f"Starting crawler at {self.base_url} with depth {self.depth}")
        
        current_depth = 0
        while current_depth < self.depth and self.to_visit:
            next_level_urls = []
            
            # Use a thread pool to speed up crawling
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {
                    executor.submit(self.fetch_url, url): url for url in self.to_visit
                }
                
                for future in concurrent.futures.as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        new_urls = future.result()
                        next_level_urls.extend(new_urls)
                    except Exception as e:
                        logger.error(f"Error crawling {url}: {str(e)}")
            
            # Prepare for next iteration
            self.to_visit = next_level_urls
            current_depth += 1
            
            logger.info(f"Crawled depth {current_depth}, found {len(self.found_urls)} URLs so far")
        
        logger.info(f"Crawling completed. Total URLs discovered: {len(self.found_urls)}")
    
    def fetch_url(self, url):
        """
        Fetch a URL and extract links from it
        
        Args:
            url (str): URL to fetch
            
        Returns:
            list: List of new URLs discovered
        """
        if url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        self.found_urls.append(url)
        new_urls = []
        
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                cookies=self.cookies,
                timeout=self.timeout,
                verify=True
            )
            
            # Skip non-HTML responses
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type.lower():
                return []
            
            # Extract links from HTML
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                # Skip empty links, anchors, and javascript
                if not href or href.startswith('#') or href.startswith('javascript:'):
                    continue
                
                # Normalize the URL
                absolute_url = self.normalize_url(url, href)
                if absolute_url and self.is_same_domain(absolute_url) and absolute_url not in self.visited_urls:
                    new_urls.append(absolute_url)
            
        except RequestException as e:
            logger.warning(f"Error requesting {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing {url}: {str(e)}")
        
        return new_urls
    
    def normalize_url(self, base_url, href):
        """
        Convert a relative URL to an absolute URL
        
        Args:
            base_url (str): Base URL for resolving relative URLs
            href (str): Relative or absolute URL to normalize
            
        Returns:
            str: Normalized absolute URL
        """
        try:
            absolute_url = urllib.parse.urljoin(base_url, href)
            parsed = urllib.parse.urlparse(absolute_url)
            
            # Remove fragments
            absolute_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # No fragment
            ))
            
            return absolute_url
        except Exception:
            return None
    
    def is_same_domain(self, url):
        """
        Check if a URL belongs to the same domain as the base URL
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if same domain, False otherwise
        """
        try:
            base_domain = urllib.parse.urlparse(self.base_url).netloc
            url_domain = urllib.parse.urlparse(url).netloc
            
            # Compare domains (optionally ignoring www)
            base_domain = base_domain.replace('www.', '')
            url_domain = url_domain.replace('www.', '')
            
            return base_domain == url_domain
        except Exception:
            return False
