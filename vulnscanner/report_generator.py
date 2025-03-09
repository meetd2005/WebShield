import json
from datetime import datetime
from jinja2 import Template
from io import BytesIO
from xhtml2pdf import pisa
from flask import Response

class ReportGenerator:
    def __init__(self):
        self.severity_colors = {
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue',
            'info': 'gray'
        }

    def generate_summary(self, scan_results):
        """Generate a summary of vulnerabilities by severity"""
        summary = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': len(scan_results.get('vulnerabilities', []))
        }

        for vuln in scan_results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1

        return summary

    def format_vulnerability(self, vuln):
        """Format a single vulnerability for display"""
        formatted_vuln = {
            'type': vuln.get('type', 'Unknown'),
            'severity': vuln.get('severity', 'info'),
            'details': vuln.get('details', ''),
            'color': self.severity_colors.get(vuln.get('severity', 'info').lower(), 'gray')
        }

        # Add request/response details if available
        if vuln.get('request_data') and vuln.get('response_data'):
            formatted_request, formatted_response = self.format_http_details(
                vuln['request_data'],
                vuln['response_data']
            )
            formatted_vuln['request'] = formatted_request
            formatted_vuln['response'] = formatted_response

        return formatted_vuln

    def generate_html_report(self, scan_results):
        """Generate an HTML report from scan results"""
        summary = self.generate_summary(scan_results)
        vulnerabilities = [
            self.format_vulnerability(vuln)
            for vuln in scan_results.get('vulnerabilities', [])
        ]

        data = {
            'scan_results': scan_results,
            'summary': summary,
            'vulnerabilities': vulnerabilities,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        return data

    def generate_pdf_report(self, scan_results):
        """Generate a PDF report from scan results"""
        summary = self.generate_summary(scan_results)

        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ text-align: center; margin-bottom: 20px; }}
                .section {{ margin: 15px 0; }}
                .vulnerability {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f5f5f5; }}
                .technical-details {{ margin-top: 10px; background-color: #f9f9f9; padding: 10px; }}
                pre {{ white-space: pre-wrap; word-wrap: break-word; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Target: {scan_results.get('target', 'N/A')}</p>
                <p>Scan Type: {scan_results.get('scan_type', 'N/A')}</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <div class="section">
                <h2>Summary</h2>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
                    {self._generate_summary_table_rows(summary)}
                </table>
            </div>

            <div class="section">
                <h2>Vulnerabilities ({len(scan_results.get('vulnerabilities', []))})</h2>
                {self._generate_vulnerabilities_html(scan_results.get('vulnerabilities', []))}
            </div>
        </body>
        </html>
        """

        pdf_buffer = BytesIO()
        pisa.CreatePDF(html_content, dest=pdf_buffer)
        pdf_buffer.seek(0)

        return Response(
            pdf_buffer,
            mimetype='application/pdf',
            headers={'Content-Disposition': 'attachment; filename=security_scan_report.pdf'}
        )

    def _generate_summary_table_rows(self, summary):
        """Generate HTML table rows for vulnerability summary"""
        rows = ""
        for severity in ['high', 'medium', 'low', 'info']:
            count = summary.get(severity, 0)
            rows += f"""
            <tr>
                <td class="severity-{severity}">{severity.capitalize()} Risk</td>
                <td>{count}</td>
            </tr>
            """
        return rows

    def _generate_vulnerabilities_html(self, vulnerabilities):
        """Generate HTML for vulnerabilities section"""
        html = ""
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            html += f"""
            <div class="vulnerability severity-{severity}">
                <h3>{vuln.get('type', 'Unknown')} ({vuln.get('severity', 'Unknown')})</h3>
                <p><strong>Details:</strong> {vuln.get('details', 'No details available')}</p>
                {self._format_request_response_html(vuln) if vuln.get('request_data') else ''}
            </div>
            """
        return html

    def _format_request_response_html(self, vuln):
        """Format request/response details for HTML display"""
        request_data = vuln.get('request_data', {})
        response_data = vuln.get('response_data', {})

        html = "<div class='technical-details'>"
        if request_data:
            html += f"""
                <p><strong>Request:</strong></p>
                <pre>{request_data.get('method', 'GET')} {request_data.get('url', '')}</pre>
                <pre>Headers: {json.dumps(request_data.get('headers', {}), indent=2)}</pre>
            """
        if response_data:
            html += f"""
                <p><strong>Response:</strong></p>
                <pre>Status: {response_data.get('status_code')}</pre>
                <pre>Headers: {json.dumps(response_data.get('headers', {}), indent=2)}</pre>
            """
        html += "</div>"
        return html

    def format_http_details(self, request_data, response_data):
        """Format HTTP request and response details"""
        formatted_request = {
            'method': request_data.get('method', 'GET'),
            'url': request_data.get('url', ''),
            'headers': request_data.get('headers', {}),
        }

        formatted_response = {
            'status_code': response_data.get('status_code', 0),
            'headers': response_data.get('headers', {}),
        }

        return formatted_request, formatted_response

    def export_json(self, scan_results):
        """Export scan results as JSON"""
        return json.dumps({
            'summary': self.generate_summary(scan_results),
            'scan_info': {
                'target': scan_results.get('target'),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'scan_type': scan_results.get('scan_type')
            },
            'vulnerabilities': [
                self.format_vulnerability(vuln)
                for vuln in scan_results.get('vulnerabilities', [])
            ]
        }, indent=2)