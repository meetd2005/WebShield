from vulnscanner import app, db
from flask import render_template, request, redirect, url_for, jsonify
from vulnscanner.models import Report, User, Scan
from vulnscanner.forms import RegisterForm, LoginForm
from flask_login import login_required, login_user, logout_user, current_user
from vulnscanner.scanner import SecurityScanner
from vulnscanner.report_generator import ReportGenerator
from vulnscanner.scanner_worker import scan_worker_pool
from datetime import datetime
import json
import logging

scanner = SecurityScanner()
report_generator = ReportGenerator()

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    user_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.started_at.desc()).all()
    return render_template('dashboard.html', scans=user_scans)

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
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return "Unauthorized", 403

    # If scan is completed, redirect to the report view
    if scan.status == "completed" and scan.reports:
        return redirect(url_for('view_report', report_id=scan.reports[0].id))

    return render_template('scan_progress.html', scan=scan)

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

            # Get the scan results
            future = scan_worker_pool.active_scans.get(scan.id)
            if future and future.done():
                results = future.result()

                # Create report
                severity_summary = {
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
                for vuln in results['vulnerabilities']:
                    severity = vuln.get('severity', 'info').lower()
                    if severity in severity_summary:
                        severity_summary[severity] += 1

                report = Report(
                    scan_id=scan.id,
                    summary=severity_summary,
                    vulnerabilities=results['vulnerabilities'],
                    created_at=datetime.utcnow()
                )
                db.session.add(report)

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
    report = Report.query.get_or_404(report_id)
    scan = Scan.query.get(report.scan_id)

    if scan.user_id != current_user.id:
        return "Unauthorized", 403

    return render_template('scan_result.html', report=report, scan=scan)


@app.route("/report/export/<int:report_id>")
@login_required
def export_report(report_id):
    report = Report.query.get_or_404(report_id)
    scan = Scan.query.get(report.scan_id)

    if scan.user_id != current_user.id:
        return "Unauthorized", 403

    format = request.args.get('format', 'html')

    if format == 'json':
        return jsonify({
            'scan': {
                'target': scan.target,
                'type': scan.scan_type,
                'started_at': scan.started_at.isoformat(),
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
            },
            'summary': report.summary,
            'vulnerabilities': report.vulnerabilities
        })
    else:
        return report_generator.generate_html_report({
            'target': scan.target,
            'scan_type': scan.scan_type,
            'timestamp': scan.started_at.isoformat(),
            'vulnerabilities': report.vulnerabilities
        })

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