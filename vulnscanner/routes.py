import logging
from datetime import datetime
import json
import time

from flask import Response, render_template, request, redirect, url_for, jsonify, stream_with_context
from flask_login import login_required, login_user, logout_user, current_user

from vulnscanner import app, db
from vulnscanner.models import Report, User, Scan
from vulnscanner.forms import RegisterForm, LoginForm
from vulnscanner.scanner import SecurityScanner
from vulnscanner.report_generator import ReportGenerator
from vulnscanner.scanner_worker import scan_worker_pool

# Configure route logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

try:
    # Initialize scanner and report generator
    scanner = SecurityScanner()
    report_generator = ReportGenerator()
    logger.info("Successfully initialized SecurityScanner and ReportGenerator")
except Exception as e:
    logger.error(f"Failed to initialize SecurityScanner: {str(e)}")
    raise

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    try:
        logger.debug(f"Loading dashboard for user {current_user.username}")

        # Get user's scans with their associated reports
        user_scans = (
            Scan.query
            .filter_by(user_id=current_user.id)
            .order_by(Scan.started_at.desc())
            .all()
        )
        logger.debug(f"Found {len(user_scans)} scans for user")

        # Ensure scan statuses are up-to-date
        for scan in user_scans:
            try:
                if scan.status == 'in_progress':
                    logger.debug(f"Checking status for scan {scan.id}")
                    status = scan_worker_pool.get_scan_status(scan.id)

                    if status['status'] != scan.status:
                        logger.info(f"Updating scan {scan.id} status from {scan.status} to {status['status']}")
                        scan.status = status['status']

                        if status['status'] == 'completed':
                            scan.completed_at = datetime.utcnow()
                            # Create report if one doesn't exist
                            if not scan.reports:
                                try:
                                    future = scan_worker_pool.active_scans.get(scan.id)
                                    if future and future.done():
                                        results = future.result()
                                        if results and 'vulnerabilities' in results:
                                            logger.info(f"Creating report for completed scan {scan.id}")
                                            report = Report(
                                                scan_id=scan.id,
                                                summary={
                                                    'high': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'high'),
                                                    'medium': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'medium'),
                                                    'low': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'low'),
                                                    'info': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'info')
                                                },
                                                vulnerabilities=results['vulnerabilities'],
                                                created_at=datetime.utcnow()
                                            )
                                            db.session.add(report)
                                            logger.info(f"Report created successfully for scan {scan.id}")
                                except Exception as e:
                                    logger.error(f"Failed to create report for scan {scan.id}: {str(e)}")
                                    scan.error = str(e)
                                    scan.status = 'failed'
                        elif status['status'] == 'failed':
                            scan.error = status.get('error', 'Unknown error occurred')

                        db.session.commit()
            except Exception as e:
                logger.error(f"Error updating scan {scan.id}: {str(e)}")
                continue

        return render_template('dashboard.html', scans=user_scans)
    except Exception as e:
        logger.error(f"Error in dashboard route: {str(e)}", exc_info=True)
        return render_template('dashboard.html', scans=[], error="Failed to load dashboard")

@app.route("/ping")
def ping():
    """Simple endpoint to verify server is running"""
    return "pong"

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')


@app.route("/api/scan/validate", methods=['POST'])
@login_required
def validate_target():
    """Endpoint to validate target URL before scanning"""
    target = request.json.get('target', '')
    is_valid = scanner.validate_url(target)
    return jsonify({'valid': is_valid})

@app.route("/scan", methods=['POST'])
@login_required
def start_scan():
    target = request.form.get('target')
    scan_type = request.form.get('scan_type', 'quick')

    if not scanner.validate_url(target):
        return jsonify({"error": "Invalid target URL"}), 400

    # Create scan record
    scan = Scan(
        user_id=current_user.id,
        target=target,
        scan_type=scan_type,
        status="in_progress",
        started_at=datetime.utcnow(),
        configuration=request.form.get('config', '{}')
    )
    db.session.add(scan)
    db.session.commit()

    # Submit scan to worker pool
    try:
        config = json.loads(request.form.get('config', '{}'))
        scan_worker_pool.submit_scan(scan.id, scanner, scan_type, target, config)
        return redirect(url_for('view_scan', scan_id=scan.id))
    except Exception as e:
        logging.error(f"Failed to start scan: {str(e)}")
        scan.status = "failed"
        db.session.commit()
        return jsonify({"error": str(e)}), 500

@app.route("/scan/<int:scan_id>")
@login_required
def view_scan(scan_id):
    logger.debug(f"Viewing scan {scan_id}")
    scan = Scan.query.get_or_404(scan_id)

    if scan.user_id != current_user.id:
        return "Unauthorized", 403

    # Get current scan status and update if needed
    status = scan_worker_pool.get_scan_status(scan.id)
    if status['status'] != scan.status:
        scan.status = status['status']
        if status['status'] == 'completed':
            scan.completed_at = datetime.utcnow()
            # Get scan results and create report if not exists
            scan_result = scan_worker_pool.get_scan_result(scan.id)
            if scan_result and not scan.reports:
                report = Report(
                    scan_id=scan.id,
                    summary={
                        'high': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'high'),
                        'medium': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'medium'),
                        'low': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'low'),
                        'info': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'info')
                    },
                    vulnerabilities=scan_result['vulnerabilities'],
                    created_at=datetime.utcnow()
                )
                db.session.add(report)
                db.session.commit()
                logger.info(f"Report created successfully for scan {scan_id}")

    # If scan is completed and has a report, redirect to report view
    if scan.status == "completed" and scan.reports:
        return redirect(url_for('view_report', report_id=scan.reports[0].id))

    return render_template('scan_result.html', scan=scan)

@app.route("/api/scan/status/<int:scan_id>")
@login_required
def scan_status(scan_id):
    """Get the current status of a scan"""
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    status = scan_worker_pool.get_scan_status(scan.id)

    # Update scan status in database if needed
    if status["status"] != scan.status:
        scan.status = status["status"]
        if status["status"] == "completed":
            scan.completed_at = datetime.utcnow()

            # Get scan results and create report if not exists
            scan_result = scan_worker_pool.get_scan_result(scan.id)
            if scan_result and not scan.reports:
                try:
                    report = Report(
                        scan_id=scan.id,
                        summary={
                            'high': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'high'),
                            'medium': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'medium'),
                            'low': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'low'),
                            'info': sum(1 for v in scan_result['vulnerabilities'] if v['severity'].lower() == 'info')
                        },
                        vulnerabilities=scan_result['vulnerabilities'],
                        created_at=datetime.utcnow()
                    )
                    db.session.add(report)
                    db.session.commit()
                    logger.info(f"Report created successfully for scan {scan_id}")
                except Exception as e:
                    logger.error(f"Failed to create report for scan {scan_id}: {str(e)}")
                    return jsonify({"status": "failed", "error": str(e)})
            elif not scan_result:
                logger.error(f"No scan results found for completed scan {scan_id}")
                return jsonify({"status": "failed", "error": "No scan results found"})

        db.session.commit()

    return jsonify(status)

@app.route("/api/scan/cancel/<int:scan_id>", methods=['POST'])
@login_required
def cancel_scan(scan_id):
    """Cancel a running scan"""
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403

    if scan_worker_pool.cancel_scan(scan.id):
        scan.status = "cancelled"
        scan.completed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "cancelled"})

    return jsonify({"error": "Could not cancel scan"}), 400

@app.route("/report/<int:report_id>")
@login_required
def view_report(report_id):
    """View a specific scan report"""
    logger.debug(f"Viewing report {report_id}")
    report = Report.query.get_or_404(report_id)
    scan = Scan.query.get(report.scan_id)

    if scan.user_id != current_user.id:
        return "Unauthorized", 403

    # Format vulnerabilities with request/response details
    formatted_vulnerabilities = []
    for vuln in report.vulnerabilities:
        formatted_vuln = {
            'type': vuln.get('type', 'Unknown'),
            'severity': vuln.get('severity', 'info'),
            'details': vuln.get('details', 'No details available')
        }

        # Add request/response if available
        if 'request_data' in vuln:
            formatted_vuln['request'] = {
                'method': vuln['request_data'].get('method', 'GET'),
                'url': vuln['request_data'].get('url', ''),
                'headers': vuln['request_data'].get('headers', {})
            }
        if 'response_data' in vuln:
            formatted_vuln['response'] = {
                'status_code': vuln['response_data'].get('status_code', 0),
                'headers': vuln['response_data'].get('headers', {})
            }

        formatted_vulnerabilities.append(formatted_vuln)

    # Pass both report and formatted data to template
    return render_template(
        'scan_result.html',
        scan=scan,
        report={
            'id': report.id,
            'summary': report.summary,
            'vulnerabilities': formatted_vulnerabilities,
            'created_at': report.created_at
        }
    )

@app.route("/report/export/<int:report_id>")
@login_required
def export_report(report_id):
    """Export report in various formats"""
    report = Report.query.get_or_404(report_id)
    scan = Scan.query.get(report.scan_id)

    if scan.user_id != current_user.id:
        return "Unauthorized", 403

    # Create report data
    report_data = {
        'target': scan.target,
        'scan_type': scan.scan_type,
        'timestamp': scan.completed_at.isoformat() if scan.completed_at else scan.started_at.isoformat(),
        'vulnerabilities': report.vulnerabilities,
        'summary': report.summary
    }

    format = request.args.get('format', 'html')
    if format == 'pdf':
        return report_generator.generate_pdf_report(report_data)
    elif format == 'json':
        return jsonify(report_generator.export_json(report_data))
    else:  # html format
        return jsonify(report_generator.generate_html_report(report_data))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            error = "Invalid username or password. Please try again."

    return render_template('login.html', form=form, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = "Username already exists. Please choose a different username."
            return render_template('register.html', error=error)

        if password != confirm_password:
            error = "Passwords do not match. Please try again."
            return render_template('register.html', error=error)

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/test/scan-report")
@login_required
def test_scan_report():
    """Test route to generate a sample vulnerability report"""
    # Create a test scan
    scan = Scan(
        user_id=current_user.id,
        target="https://example.com",
        scan_type="test",
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow()
    )
    db.session.add(scan)
    db.session.commit()  # Commit here to get the scan ID

    # Sample vulnerabilities with different severities
    vulnerabilities = [
        {
            "type": "SQL Injection",
            "severity": "high",
            "details": "Found potential SQL injection in login form",
            "request_data": {
                "method": "POST",
                "url": "/login",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "test' OR '1'='1"}
            },
            "response_data": {
                "status_code": 500,
                "headers": {"Server": "nginx"},
                "body": "Database error occurred"
            }
        },
        {
            "type": "XSS Vulnerability",
            "severity": "medium",
            "details": "Cross-site scripting vulnerability in comment section",
            "request_data": {
                "method": "POST",
                "url": "/comments",
                "headers": {"Content-Type": "application/json"},
                "body": {"content": "<script>alert('xss')</script>"}
            },
            "response_data": {
                "status_code": 200,
                "headers": {"Server": "nginx"},
                "body": "Comment posted successfully"
            }
        },
        {
            "type": "Missing Security Headers",
            "severity": "low",
            "details": "Security headers X-Frame-Options and CSP are missing",
            "request_data": {
                "method": "GET",
                "url": "/",
                "headers": {}
            },
            "response_data": {
                "status_code": 200,
                "headers": {"Server": "nginx"},
                "body": "Homepage content"
            }
        }
    ]

    # Create test report
    report = Report(
        scan_id=scan.id,  # Now we have a valid scan ID
        summary={
            "high": 1,
            "medium": 1,
            "low": 1,
            "info": 0
        },
        vulnerabilities=vulnerabilities,
        created_at=datetime.utcnow()
    )
    db.session.add(report)
    db.session.commit()

    return redirect(url_for('view_report', report_id=report.id))

@app.route("/scan/events/<int:scan_id>")
@login_required
def scan_events(scan_id):
    """SSE endpoint for real-time scan updates"""
    def event_stream():
        last_event_id = 0
        retry_count = 0
        max_retries = 30  # 30 seconds timeout
        logging.debug(f"Starting event stream for scan {scan_id}")

        while True:
            # Check scan status first
            status = scan_worker_pool.get_scan_status(scan_id)

            # If scan is in a final state, update database and close stream
            if status['status'] in ['completed', 'failed', 'cancelled']:
                scan = Scan.query.get(scan_id)
                if scan and scan.status != status['status']:
                    scan.status = status['status']
                    if status['status'] == 'completed':
                        scan.completed_at = datetime.utcnow()
                        # Create report for completed scan
                        future = scan_worker_pool.active_scans.get(scan_id)
                        if future and future.done():
                            try:
                                results = future.result()
                                report = Report(
                                    scan_id=scan.id,
                                    summary={
                                        'high': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'high'),
                                        'medium': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'medium'),
                                        'low': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'low'),
                                        'info': sum(1 for v in results['vulnerabilities'] if v['severity'].lower() == 'info')
                                    },
                                    vulnerabilities=results['vulnerabilities'],
                                    created_at=datetime.utcnow()
                                )
                                db.session.add(report)
                            except Exception as e:
                                logging.error(f"Failed to create report for scan {scan_id}: {str(e)}")
                    db.session.commit()
                    logging.info(f"Updated scan {scan_id} status to {status['status']}")

                # Send any remaining events
                events = scan_worker_pool.get_events(scan_id, last_event_id)
                for event in events:
                    last_event_id += 1
                    yield f"event: {event['event']}\ndata: {json.dumps(event['data'])}\nid: {last_event_id}\n\n"

                logging.debug(f"Scan {scan_id} {status['status']}, closing event stream")
                break

            # Get new events
            events = scan_worker_pool.get_events(scan_id, last_event_id)
            if events:
                retry_count = 0  # Reset retry count when we get events
                for event in events:
                    last_event_id += 1
                    yield f"event: {event['event']}\ndata: {json.dumps(event['data'])}\nid: {last_event_id}\n\n"
            else:
                retry_count += 1
                if retry_count >= max_retries:
                    logging.warning(f"Event stream timeout for scan {scan_id}")
                    yield f"event: scan_error\ndata: {json.dumps({'error': 'Event stream timeout'})}\n\n"
                    break
                time.sleep(1)  # Wait before next poll

    return Response(
        stream_with_context(event_stream()),
        mimetype='text/event-stream'
    )