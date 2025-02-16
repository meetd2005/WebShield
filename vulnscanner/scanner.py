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

class SecurityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def validate_url(self, url):
        """Validate URL format and accessibility"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            parsed = urllib.parse.urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                return False
            response = requests.head(url, timeout=5)
            return True
        except Exception as e:
            logging.error(f"URL validation error: {str(e)}")
            return False

    def check_ssl_certificate(self, hostname, port=443):
        """Comprehensive SSL certificate check"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issues = []

                    # Check expiration
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if expire_date < datetime.now():
                        issues.append({
                            'type': 'ssl_cert_expired',
                            'severity': 'high',
                            'details': f'SSL Certificate expired on {expire_date}'
                        })

                    # Check weak cipher suites
                    cipher = ssock.cipher()
                    if cipher[0] in ['RC4', 'DES', '3DES']:
                        issues.append({
                            'type': 'weak_cipher',
                            'severity': 'medium',
                            'details': f'Weak cipher suite in use: {cipher[0]}'
                        })

                    return issues
        except ssl.SSLError as e:
            return [{
                'type': 'ssl_error',
                'severity': 'high',
                'details': f'SSL Error: {str(e)}'
            }]
        except Exception as e:
            logging.error(f"SSL check error: {str(e)}")
            return []

    def check_security_headers(self, url):
        """Check for security-related HTTP headers"""
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
                    issues.append({
                        'type': 'missing_header',
                        'severity': 'medium',
                        'details': message
                    })

            # Check for information disclosure
            if 'Server' in headers and headers['Server']:
                issues.append({
                    'type': 'info_disclosure',
                    'severity': 'low',
                    'details': f'Server header reveals version information: {headers["Server"]}'
                })

            return issues
        except Exception as e:
            logging.error(f"Headers check error: {str(e)}")
            return []

    def check_web_vulnerabilities(self, url):
        """Check for common web application vulnerabilities"""
        try:
            vulnerabilities = []

            # Test for directory traversal
            traversal_paths = ['../etc/passwd', '..\\windows\\win.ini', '....//....//etc/passwd']
            for path in traversal_paths:
                try:
                    test_url = urllib.parse.urljoin(url, path)
                    response = requests.get(test_url, allow_redirects=False, timeout=5)
                    if response.status_code == 200 and any(signature in response.text for signature in ['root:x:', '[fonts]']):
                        vulnerabilities.append({
                            'type': 'directory_traversal',
                            'severity': 'high',
                            'details': f'Potential directory traversal vulnerability found at: {test_url}'
                        })
                except:
                    continue

            # Test for SQL injection
            sql_payloads = ["' OR '1'='1", "1' OR '1' = '1"]
            for payload in sql_payloads:
                try:
                    # Test URL parameters
                    test_url = f"{url}?id={payload}"
                    response = requests.get(test_url, timeout=5)
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql']):
                        vulnerabilities.append({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'details': f'Potential SQL injection vulnerability detected at: {url}'
                        })
                except:
                    continue

            # Test for XSS vulnerabilities
            xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>', '<img src=x onerror=alert(1)>']
            for payload in xss_payloads:
                try:
                    test_url = f"{url}?q={urllib.parse.quote(payload)}"
                    response = requests.get(test_url, timeout=5)
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'xss',
                            'severity': 'high',
                            'details': f'Potential Cross-Site Scripting (XSS) vulnerability detected at: {url}'
                        })
                except:
                    continue

            # Enhanced security header checks
            response = requests.get(url)
            headers = response.headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header (Clickjacking risk)',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing Content-Security-Policy header',
                'Referrer-Policy': 'Missing Referrer-Policy header',
                'Permissions-Policy': 'Missing Permissions-Policy header'
            }

            for header, message in security_headers.items():
                if header not in headers:
                    vulnerabilities.append({
                        'type': 'missing_security_header',
                        'severity': 'medium',
                        'details': message
                    })

            # Check for sensitive information exposure
            sensitive_patterns = [
                r'\b[\w\.-]+@[\w\.-]+\.\w+\b',  # Email addresses
                r'\b\d{3}-\d{2}-\d{4}\b',       # SSN
                r'\b\d{16}\b',                   # Credit card numbers
                r'password\s*=\s*[\'"][^\'"]+[\'"]'  # Hard-coded passwords
            ]

            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': 'information_disclosure',
                        'severity': 'high',
                        'details': f'Potential sensitive information disclosure detected: {pattern}'
                    })

            return vulnerabilities
        except Exception as e:
            logging.error(f"Web vulnerability check error: {str(e)}")
            return []

    def quick_scan(self, target):
        """Enhanced quick security scan"""
        if not self.validate_url(target):
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'quick',
                'status': 'failed',
                'error': 'Invalid or inaccessible URL'
            }

        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'scan_type': 'quick',
            'status': 'completed',
            'vulnerabilities': []
        }

        try:
            # Basic security header checks (25%)
            yield 25
            results['vulnerabilities'].extend(self.check_security_headers(target))

            # Web vulnerability checks (50%)
            yield 50
            results['vulnerabilities'].extend(self.check_web_vulnerabilities(target))

            # SSL certificate checks if HTTPS (75%)
            if target.startswith('https'):
                yield 75
                hostname = urllib.parse.urlparse(target).netloc
                results['vulnerabilities'].extend(self.check_ssl_certificate(hostname))

            # Completion (100%)
            yield 100
            return results
        except Exception as e:
            logging.error(f"Quick scan error: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'quick',
                'status': 'failed',
                'error': str(e)
            }

    def full_scan(self, target):
        """Comprehensive security scan"""
        if not self.validate_url(target):
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

            # Initial setup (10%)
            yield 10

            # Port and service scan (30%)
            try:
                self.nm.scan(hostname, arguments='-sS -sV -O --script vuln')
                yield 30
                for host in self.nm.all_hosts():
                    os_match = self.nm[host].get('osmatch', [])
                    if os_match:
                        results['vulnerabilities'].append({
                            'type': 'os_detection',
                            'severity': 'info',
                            'details': f'Operating System detected: {os_match[0]["name"]} ({os_match[0]["accuracy"]}% accuracy)'
                        })

                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            service = self.nm[host][proto][port]
                            script_output = service.get('script', {})

                            if script_output:
                                for script_name, output in script_output.items():
                                    if 'VULNERABLE' in output:
                                        results['vulnerabilities'].append({
                                            'type': 'service_vulnerability',
                                            'severity': 'high',
                                            'details': f'Vulnerability detected in {service["name"]} on port {port}: {script_name}'
                                        })
            except Exception as e:
                logging.error(f"Full port scan error: {str(e)}")

            # Security header checks (50%)
            yield 50
            results['vulnerabilities'].extend(self.check_security_headers(target))

            # Web vulnerability checks (70%)
            yield 70
            results['vulnerabilities'].extend(self.check_web_vulnerabilities(target))

            # SSL certificate checks if HTTPS (80%)
            if target.startswith('https'):
                yield 80
                results['vulnerabilities'].extend(self.check_ssl_certificate(hostname))

            # Additional web application checks (90%)
            try:
                yield 90
                response = requests.get(target)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Check for exposed sensitive files
                sensitive_paths = ['/admin', '/phpinfo.php', '/wp-admin', '/.git', '/.env']
                for path in sensitive_paths:
                    try:
                        check_url = urllib.parse.urljoin(target, path)
                        r = requests.head(check_url, allow_redirects=False)
                        if r.status_code != 404:
                            results['vulnerabilities'].append({
                                'type': 'sensitive_path',
                                'severity': 'high',
                                'details': f'Potentially sensitive path accessible: {path}'
                            })
                    except:
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
                        results['vulnerabilities'].append({
                            'type': 'csrf_vulnerability',
                            'severity': 'medium',
                            'details': f'Form found without CSRF protection: {form.get("action", "unknown")}'
                        })
            except Exception as e:
                logging.error(f"Web application scan error: {str(e)}")

            # Completion (100%)
            yield 100
            return results
        except Exception as e:
            logging.error(f"Full scan error: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'scan_type': 'full',
                'status': 'failed',
                'error': str(e)
            }

    def custom_scan(self, target, options):
        """Custom scan with user-defined options"""
        if not self.validate_url(target):
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

        if options.get('port_scan', False):
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
                            results['vulnerabilities'].append({
                                'type': 'port_scan',
                                'severity': severity,
                                'details': f'Port {port} ({service["name"]}) is open, version: {service.get("version", "unknown")}'
                            })
            except Exception as e:
                logging.error(f"Custom port scan error: {str(e)}")

        if options.get('ssl_check', False):
            results['vulnerabilities'].extend(self.check_ssl_certificate(hostname))

        if options.get('header_check', False):
            results['vulnerabilities'].extend(self.check_security_headers(target))

        if options.get('crawl', False):
            try:
                response = requests.get(target)
                soup = BeautifulSoup(response.text, 'html.parser')

                # Find all links
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
                                    results['vulnerabilities'].append({
                                        'type': 'error_page',
                                        'severity': 'medium',
                                        'details': f'Internal server error found at: {url}'
                                    })
                            except:
                                continue
            except Exception as e:
                logging.error(f"Crawl error: {str(e)}")

        return results