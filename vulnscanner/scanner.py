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

        # Basic port scan for common services
        try:
            hostname = urllib.parse.urlparse(target).netloc
            self.nm.scan(hostname, arguments='-F -sV')
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        if port in [80, 443, 21, 22, 3306, 5432, 27017, 6379]:
                            results['vulnerabilities'].append({
                                'type': 'open_port',
                                'severity': 'medium',
                                'details': f'Port {port} ({service["name"]}) is open and potentially exposed'
                            })
        except Exception as e:
            logging.error(f"Quick port scan error: {str(e)}")

        # Add header security checks
        results['vulnerabilities'].extend(self.check_security_headers(target))

        if target.startswith('https'):
            hostname = urllib.parse.urlparse(target).netloc
            results['vulnerabilities'].extend(self.check_ssl_certificate(hostname))

        return results

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

        hostname = urllib.parse.urlparse(target).netloc

        # Comprehensive port and service scan
        try:
            self.nm.scan(hostname, arguments='-sS -sV -O --script vuln')
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

        # Add all security checks
        results['vulnerabilities'].extend(self.check_security_headers(target))

        if target.startswith('https'):
            results['vulnerabilities'].extend(self.check_ssl_certificate(hostname))

        # Additional checks for web applications
        try:
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

        return results

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