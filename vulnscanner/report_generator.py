import json
from datetime import datetime
from jinja2 import Template

class ReportGenerator:
    def __init__(self, ai_analyzer=None):
        self.severity_colors = {
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'gray'
        }
        self.ai_analyzer = ai_analyzer

    def format_http_details(self, request_data, response_data):
        """Format HTTP request and response details for display"""
        formatted_request = {
            'method': request_data.get('method', 'GET'),
            'url': request_data.get('url', ''),
            'headers': request_data.get('headers', {}),
            'body': request_data.get('body', ''),
            'cookies': request_data.get('cookies', {}),
        }

        formatted_response = {
            'status_code': response_data.get('status_code', 0),
            'headers': response_data.get('headers', {}),
            'body': response_data.get('body', ''),
            'cookies': response_data.get('cookies', {}),
        }

        return formatted_request, formatted_response

    def analyze_vulnerability(self, vulnerability, request_data, response_data):
        """Get AI analysis for a vulnerability"""
        if self.ai_analyzer:
            return self.ai_analyzer.analyze_vulnerability(
                vulnerability,
                request_data,
                response_data
            )
        return None

    def generate_summary(self, scan_results):
        """Generate a summary of vulnerabilities by severity"""
        summary = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': len(scan_results['vulnerabilities'])
        }

        for vuln in scan_results['vulnerabilities']:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1

        return summary

    def format_vulnerability(self, vuln, request_data=None, response_data=None):
        """Format a single vulnerability for display with enhanced details"""
        formatted_vuln = {
            'type': vuln['type'],
            'severity': vuln['severity'],
            'details': vuln['details'],
            'color': self.severity_colors.get(vuln['severity'].lower(), 'gray')
        }

        # Add HTTP details if available
        if request_data and response_data:
            formatted_request, formatted_response = self.format_http_details(request_data, response_data)
            formatted_vuln['request'] = formatted_request
            formatted_vuln['response'] = formatted_response

        # Add AI analysis if available
        if self.ai_analyzer:
            formatted_vuln['ai_analysis'] = self.analyze_vulnerability(vuln, request_data, response_data)

        return formatted_vuln

    def generate_html_report(self, scan_results):
        """Generate an HTML report from scan results"""
        summary = self.generate_summary(scan_results)
        vulnerabilities = []

        for vuln in scan_results['vulnerabilities']:
            request_data = vuln.get('request_data', {})
            response_data = vuln.get('response_data', {})
            formatted_vuln = self.format_vulnerability(vuln, request_data, response_data)
            vulnerabilities.append(formatted_vuln)

        # Pass all data to the template (template content moved to scan_result.html)
        data = {
            'scan_results': scan_results,
            'summary': summary,
            'vulnerabilities': vulnerabilities,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        return data

    def generate_pdf_report(self, scan_results):
        """Generate a PDF report from scan results"""
        # PDF generation logic would go here
        pass

    def export_json(self, scan_results):
        """Export scan results as JSON with enhanced details"""
        summary = self.generate_summary(scan_results)
        vulnerabilities = []

        for vuln in scan_results['vulnerabilities']:
            request_data = vuln.get('request_data', {})
            response_data = vuln.get('response_data', {})
            formatted_vuln = self.format_vulnerability(vuln, request_data, response_data)
            vulnerabilities.append(formatted_vuln)

        export_data = {
            'summary': summary,
            'scan_info': {
                'target': scan_results.get('target'),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_type': scan_results.get('scan_type')
            },
            'vulnerabilities': vulnerabilities
        }

        return json.dumps(export_data, indent=2)