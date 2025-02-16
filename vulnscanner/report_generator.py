import json
from datetime import datetime
from jinja2 import Template

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
            'total': len(scan_results['vulnerabilities'])
        }
        
        for vuln in scan_results['vulnerabilities']:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
                
        return summary

    def format_vulnerability(self, vuln):
        """Format a single vulnerability for display"""
        return {
            'type': vuln['type'],
            'severity': vuln['severity'],
            'details': vuln['details'],
            'color': self.severity_colors.get(vuln['severity'].lower(), 'gray')
        }

    def generate_html_report(self, scan_results):
        """Generate an HTML report from scan results"""
        template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-dark text-light">
            <div class="container py-4">
                <h1>Security Scan Report</h1>
                <div class="card bg-dark text-light border-secondary mb-4">
                    <div class="card-body">
                        <h5 class="card-title">Scan Details</h5>
                        <p>Target: {{ scan_results.target }}</p>
                        <p>Scan Type: {{ scan_results.scan_type }}</p>
                        <p>Timestamp: {{ scan_results.timestamp }}</p>
                    </div>
                </div>

                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-danger text-white">
                            <div class="card-body text-center">
                                <h5>High</h5>
                                <h2>{{ summary.high }}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-warning text-dark">
                            <div class="card-body text-center">
                                <h5>Medium</h5>
                                <h2>{{ summary.medium }}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-info text-white">
                            <div class="card-body text-center">
                                <h5>Low</h5>
                                <h2>{{ summary.low }}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-secondary text-white">
                            <div class="card-body text-center">
                                <h5>Info</h5>
                                <h2>{{ summary.info }}</h2>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card bg-dark text-light border-secondary">
                    <div class="card-body">
                        <h5 class="card-title">Vulnerabilities</h5>
                        {% for vuln in vulnerabilities %}
                        <div class="alert alert-{{ vuln.color }} mb-3">
                            <h5>{{ vuln.type }}</h5>
                            <p class="mb-0">Severity: {{ vuln.severity }}</p>
                            <p class="mb-0">{{ vuln.details }}</p>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(template)
        summary = self.generate_summary(scan_results)
        vulnerabilities = [self.format_vulnerability(v) for v in scan_results['vulnerabilities']]
        
        return template.render(
            scan_results=scan_results,
            summary=summary,
            vulnerabilities=vulnerabilities
        )

    def generate_pdf_report(self, scan_results):
        """Generate a PDF report from scan results"""
        # PDF generation logic would go here
        pass

    def export_json(self, scan_results):
        """Export scan results as JSON"""
        return json.dumps(scan_results, indent=2)
