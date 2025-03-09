import subprocess
import nmap
import requests
from bs4 import BeautifulSoup
import ssl
import socket
import json
from datetime import datetime
import logging
import re
import urllib.parse

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] Scanner: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class SecurityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.logger = logging.getLogger('SecurityScanner')

    def validate_url(self, url):
        """Validate URL format and accessibility"""
        try:
            self.logger.debug(f"Validating URL: {url}")
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed = urllib.parse.urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                self.logger.warning(f"Invalid URL format: {url}")
                return False
            response = requests.head(url, timeout=5)
            self.logger.info(f"URL validation successful: {url}")
            return True
        except Exception as e:
            self.logger.error(f"URL validation error: {str(e)}")
            return False

    def check_web_vulnerabilities(self, url):
        """Check for common web application vulnerabilities"""
        self.logger.debug(f"Starting web vulnerability check for {url}")
        vulnerabilities = []

        try:
            # Test for directory traversal
            self.logger.debug("Starting directory traversal checks")
            traversal_paths = ['../etc/passwd', '..\\windows\\win.ini', '....//....//etc/passwd']
            for path in traversal_paths:
                try:
                    test_url = urllib.parse.urljoin(url, path)
                    response = requests.get(test_url, allow_redirects=False, timeout=5)
                    if response.status_code == 200 and any(signature in response.text for signature in ['root:x:', '[fonts]']):
                        vuln = {
                            'type': 'directory_traversal',
                            'severity': 'high',
                            'details': f'Potential directory traversal vulnerability found at: {test_url}'
                        }
                        vulnerabilities.append(vuln)
                        yield {'vulnerabilities': [vuln]}
                except Exception as e:
                    self.logger.debug(f"Directory traversal test failed for {path}: {str(e)}")
                    continue

            # Test for SQL injection
            self.logger.debug("Starting SQL injection checks")
            sql_payloads = ["' OR '1'='1", "1' OR '1' = '1"]
            for payload in sql_payloads:
                try:
                    test_url = f"{url}?id={payload}"
                    response = requests.get(test_url, timeout=5)
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql']):
                        vuln = {
                            'type': 'sql_injection',
                            'severity': 'high',
                            'details': f'Potential SQL injection vulnerability detected at: {url}'
                        }
                        vulnerabilities.append(vuln)
                        yield {'vulnerabilities': [vuln]}
                except Exception as e:
                    self.logger.debug(f"SQL injection test failed for {payload}: {str(e)}")
                    continue

            # Test for XSS vulnerabilities
            self.logger.debug("Starting XSS vulnerability checks")
            xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>', '<img src=x onerror=alert(1)>']
            for payload in xss_payloads:
                try:
                    test_url = f"{url}?q={urllib.parse.quote(payload)}"
                    response = requests.get(test_url, timeout=5)
                    if payload in response.text:
                        vuln = {
                            'type': 'xss',
                            'severity': 'high',
                            'details': f'Potential Cross-Site Scripting (XSS) vulnerability detected at: {url}'
                        }
                        vulnerabilities.append(vuln)
                        yield {'vulnerabilities': [vuln]}
                except Exception as e:
                    self.logger.debug(f"XSS test failed for {payload}: {str(e)}")
                    continue

            self.logger.info(f"Web vulnerability check completed for {url}. Issues found: {len(vulnerabilities)}")
            return {'vulnerabilities': vulnerabilities, 'status': 'completed'}

        except Exception as e:
            self.logger.error(f"Web vulnerability check failed: {str(e)}")
            return {'vulnerabilities': vulnerabilities, 'status': 'failed', 'error': str(e)}

    def quick_scan(self, target, options=None):
        """Quick security scan"""
        self.logger.info(f"Starting quick scan for target: {target}")
        vulnerabilities = []

        if not self.validate_url(target):
            self.logger.error(f"Invalid or inaccessible target URL: {target}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'quick',
                'status': 'failed',
                'error': 'Invalid or inaccessible URL',
                'vulnerabilities': []
            }

        try:
            # Security header checks
            self.logger.debug("Starting security header checks")
            header_results = self.check_security_headers(target)
            for vuln in header_results:
                vulnerabilities.append(vuln)
                yield {'vulnerabilities': [vuln]}

            # Web vulnerability checks
            self.logger.debug("Starting web vulnerability checks")
            web_vuln_gen = self.check_web_vulnerabilities(target)
            try:
                for item in web_vuln_gen:
                    if isinstance(item, dict) and 'vulnerabilities' in item:
                        vulnerabilities.extend(item['vulnerabilities'])
                        yield item
            except Exception as e:
                self.logger.error(f"Error processing vulnerability check: {str(e)}")

            # Completion phase
            self.logger.info(f"Quick scan completed for {target} with {len(vulnerabilities)} total findings")
            result = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'quick',
                'status': 'completed',
                'vulnerabilities': vulnerabilities
            }
            return result

        except Exception as e:
            self.logger.error(f"Quick scan error: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'quick',
                'status': 'failed',
                'error': str(e),
                'vulnerabilities': vulnerabilities
            }

    def check_ssl_certificate(self, hostname, port=443):
        """Comprehensive SSL certificate check"""
        self.logger.debug(f"Starting SSL certificate check for {hostname}:{port}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issues = []

                    # Check expiration
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if expire_date < datetime.now():
                        self.logger.warning(f"SSL certificate expired on {expire_date} for {hostname}")
                        issues.append({
                            'type': 'ssl_cert_expired',
                            'severity': 'high',
                            'details': f'SSL Certificate expired on {expire_date}'
                        })

                    # Check weak cipher suites
                    cipher = ssock.cipher()
                    if cipher[0] in ['RC4', 'DES', '3DES']:
                        self.logger.warning(f"Weak cipher suite in use: {cipher[0]} for {hostname}")
                        issues.append({
                            'type': 'weak_cipher',
                            'severity': 'medium',
                            'details': f'Weak cipher suite in use: {cipher[0]}'
                        })

                    self.logger.info(f"SSL certificate check completed for {hostname}. Issues found: {len(issues)}")
                    return issues
        except ssl.SSLError as e:
            self.logger.error(f"SSL Error for {hostname}: {str(e)}", exc_info=True)
            return [{
                'type': 'ssl_error',
                'severity': 'high',
                'details': f'SSL Error: {str(e)}'
            }]
        except Exception as e:
            self.logger.error(f"SSL check error for {hostname}: {str(e)}", exc_info=True)
            return []

    def check_security_headers(self, url):
        """Check for security-related HTTP headers"""
        self.logger.debug(f"Starting security header check for {url}")
        try:
            response = requests.get(url)
            headers = response.headers
            issues = []

            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking risk)',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header'
            }

            for header, message in security_headers.items():
                if header not in headers:
                    self.logger.warning(f"Missing security header: {header} for {url}")
                    issues.append({
                        'type': 'missing_header',
                        'severity': 'medium',
                        'details': message
                    })

            # Check for information disclosure
            if 'Server' in headers and headers['Server']:
                self.logger.warning(f"Server header reveals version information: {headers['Server']} for {url}")
                issues.append({
                    'type': 'info_disclosure',
                    'severity': 'low',
                    'details': f'Server header reveals version information: {headers["Server"]}'
                })

            self.logger.info(f"Security header check completed for {url}. Issues found: {len(issues)}")
            return issues
        except Exception as e:
            self.logger.error(f"Headers check error for {url}: {str(e)}", exc_info=True)
            return []
    def full_scan(self, target, options=None):
        """Comprehensive security scan"""
        self.logger.info(f"Starting full scan for target: {target}")

        if not self.validate_url(target):
            self.logger.error(f"Invalid or inaccessible target URL: {target}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'full',
                'status': 'failed',
                'error': 'Invalid or inaccessible URL'
            }

        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': 'full',
            'status': 'completed',
            'vulnerabilities': []
        }

        try:
            hostname = urllib.parse.urlparse(target).netloc
            self.logger.debug(f"Parsed hostname: {hostname}")

            # Initial setup 
            self.logger.debug("Initializing full scan")
            
            # Port and service scan 
            try:
                self.logger.debug("Starting port and service scan")
                self.nm.scan(hostname, arguments='-sS -sV -O --script vuln')
                
                for host in self.nm.all_hosts():
                    os_match = self.nm[host].get('osmatch', [])
                    if os_match:
                        self.logger.info(f"Detected OS: {os_match[0]['name']}")
                        results['vulnerabilities'].append({
                            'type': 'os_detection',
                            'severity': 'info',
                            'details': f"Operating System detected: {os_match[0]['name']} ({os_match[0]['accuracy']}% accuracy)"
                        })

                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            service = self.nm[host][proto][port]
                            script_output = service.get('script', {})

                            if script_output:
                                for script_name, output in script_output.items():
                                    if 'VULNERABLE' in output:
                                        self.logger.warning(f"Found vulnerability in service {service['name']} on port {port}")
                                        results['vulnerabilities'].append({
                                            'type': 'service_vulnerability',
                                            'severity': 'high',
                                            'details': f"Vulnerability detected in {service['name']} on port {port}: {script_name}"
                                        })

            except Exception as e:
                self.logger.error(f"Port scan error: {str(e)}", exc_info=True)

            # Security header checks 
            self.logger.debug("Starting security header checks")
            header_results = self.check_security_headers(target)
            results['vulnerabilities'].extend(header_results)
            self.logger.info(f"Found {len(header_results)} header vulnerabilities")

            # Web vulnerability checks 
            self.logger.debug("Starting web vulnerability checks")
            for progress in self.check_web_vulnerabilities(target):
                yield progress

            self.logger.info(f"Found {len(results['vulnerabilities'])} web vulnerabilities")


            # SSL certificate checks if HTTPS 
            if target.startswith('https'):
                self.logger.debug("Starting SSL certificate checks")
                ssl_results = self.check_ssl_certificate(hostname)
                results['vulnerabilities'].extend(ssl_results)
                self.logger.info(f"Found {len(ssl_results)} SSL vulnerabilities")

            # Additional web application checks 
            try:
                self.logger.debug("Starting additional web application checks")
                response = requests.get(target)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Check for exposed sensitive files
                sensitive_paths = ['/admin', '/phpinfo.php', '/wp-admin', '/.git', '/.env']
                for path in sensitive_paths:
                    try:
                        check_url = urllib.parse.urljoin(target, path)
                        r = requests.head(check_url, allow_redirects=False)
                        if r.status_code != 404:
                            self.logger.warning(f"Potentially sensitive path accessible: {path}")
                            results['vulnerabilities'].append({
                                'type': 'sensitive_path',
                                'severity': 'high',
                                'details': f'Potentially sensitive path accessible: {path}'
                            })
                    except Exception as e:
                        self.logger.debug(f"Sensitive path check failed for {check_url}: {str(e)}")
                        continue

                # Check for forms without CSRF protection
                forms = soup.find_all('form')
                for form in forms:
                    csrf_found = False
                    for input_tag in form.find_all('input'):
                        if input_tag.get('name', '').lower() in ['csrf', 'csrf_token', '_token']:
                            csrf_found = True
                            break
                    if not csrf_found:
                        self.logger.warning(f"Form found without CSRF protection: {form.get('action', 'unknown')}")
                        results['vulnerabilities'].append({
                            'type': 'csrf_vulnerability',
                            'severity': 'medium',
                            'details': f'Form found without CSRF protection: {form.get("action", "unknown")}'
                        })
            except Exception as e:
                self.logger.error(f"Web application scan error: {str(e)}", exc_info=True)

            # Completion 
            self.logger.info(f"Full scan completed for {target}")
            yield results
            return results
        except Exception as e:
            self.logger.error(f"Full scan error: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'full',
                'status': 'failed',
                'error': str(e)
            }

    def custom_scan(self, target, options):
        """Custom scan with user-defined options"""
        self.logger.info(f"Starting custom scan for target: {target} with options: {options}")

        if not self.validate_url(target):
            self.logger.error(f"Invalid or inaccessible target URL: {target}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'custom',
                'status': 'failed',
                'error': 'Invalid or inaccessible URL'
            }

        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': 'custom',
            'status': 'completed',
            'vulnerabilities': []
        }

        hostname = urllib.parse.urlparse(target).netloc

        try:
            current_progress = 0
            total_checks = sum(1 for opt in options.values() if opt)
            progress_increment = 95 / total_checks if total_checks > 0 else 95

            if options.get('port_scan', False):
                self.logger.debug("Starting port scan")
                try:
                    port_range = options.get('port_range', '1-1000')
                    arguments = f'-p{port_range} -sV'
                    if options.get('aggressive', False):
                        arguments += ' -T4'
                    if options.get('service_detection', False):
                        arguments += ' -sC'

                    self.nm.scan(hostname, arguments=arguments)
                    for host in self.nm.all_hosts():
                        for proto in self.nm[host].all_protocols():
                            ports = self.nm[host][proto].keys()
                            for port in ports:
                                service = self.nm[host][proto][port]
                                severity = 'high' if port in [21, 22, 23, 3389] else 'medium'
                                self.logger.warning(f"Found open port {port} ({service['name']})")
                                results['vulnerabilities'].append({
                                    'type': 'port_scan',
                                    'severity': severity,
                                    'details': f"Port {port} ({service['name']}) is open, version: {service.get('version', 'unknown')}"
                                })
                except Exception as e:
                    self.logger.error(f"Port scan error: {str(e)}", exc_info=True)

                current_progress += progress_increment
                yield {'progress': current_progress}

            if options.get('ssl_check', False):
                self.logger.debug("Starting SSL check")
                ssl_results = self.check_ssl_certificate(hostname)
                results['vulnerabilities'].extend(ssl_results)
                self.logger.info(f"Found {len(ssl_results)} SSL vulnerabilities")

                current_progress += progress_increment
                yield {'progress': current_progress}

            if options.get('header_check', False):
                self.logger.debug("Starting header check")
                header_results = self.check_security_headers(target)
                results['vulnerabilities'].extend(header_results)
                self.logger.info(f"Found {len(header_results)} header vulnerabilities")

                current_progress += progress_increment
                yield {'progress': current_progress}

            if options.get('crawl', False):
                self.logger.debug("Starting web crawl")
                try:
                    response = requests.get(target)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = soup.find_all('a', href=True)
                    checked_urls = set()

                    for link in links:
                        url = link['href']
                        if url.startswith('/') or url.startswith(target):
                            if url not in checked_urls:
                                checked_urls.add(url)
                                try:
                                    full_url = urllib.parse.urljoin(target, url)
                                    r = requests.head(full_url, allow_redirects=False)
                                    if r.status_code in [500, 501, 502, 503]:
                                        self.logger.warning(f"Found error page: {url}")
                                        results['vulnerabilities'].append({
                                            'type': 'error_page',
                                            'severity': 'medium',
                                            'details': f"Internal server error found at: {url}"
                                        })
                                except Exception as e:
                                    self.logger.error(f"Error checking URL {url}: {str(e)}")
                                    continue
                except Exception as e:
                    self.logger.error(f"Crawl error: {str(e)}", exc_info=True)

                current_progress += progress_increment
                yield {'progress': current_progress}

            # Final progress update
            self.logger.info(f"Custom scan completed for {target}")
            yield {'progress': 100, 'results': results}
            return results
        except Exception as e:
            self.logger.error(f"Custom scan error: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'custom',
                'status': 'failed',
                'error': str(e)
            }