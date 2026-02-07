"""
PhishCheck - Internal Phishing Detection Tool

Main Flask application with dashboard and API routes.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from functools import wraps
import json
import logging
import os

import config
from models import (
    init_db, create_submission, get_submission, get_submissions,
    get_submission_stats, find_or_create_campaign, get_active_campaigns,
    get_campaign_alert_level, create_feedback, get_feedback_stats,
    get_pending_feedback, add_to_whitelist, add_to_blacklist,
    get_whitelist, get_blacklist, remove_from_whitelist, remove_from_blacklist,
    get_unique_users, check_auto_whitelist, get_learning_stats
)
from analyzer import analyze_email
from graph_client import get_graph_client, format_verdict_email
from alerts import check_campaign_alerts

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Initialize database
init_db()


# =============================================================================
# Authentication
# =============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == config.DEMO_USERNAME and password == config.DEMO_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# =============================================================================
# Dashboard Routes
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    """Main dashboard with overview stats."""
    stats = get_submission_stats(days=30)
    stats_week = get_submission_stats(days=7)
    stats_today = get_submission_stats(days=1)

    # Get active campaigns with alert levels
    campaigns = get_active_campaigns()
    for campaign in campaigns:
        campaign['alert_level'] = get_campaign_alert_level(campaign['id'])

    # Filter to only show campaigns with alerts
    alert_campaigns = [c for c in campaigns if c['alert_level'] != 'normal']

    # Get feedback stats
    feedback_stats = get_feedback_stats(days=30)

    # Get unique users
    unique_users = get_unique_users(days=30)

    # Get recent URL detonations
    detonations = []
    try:
        from pathlib import Path
        output_dir = Path(config.DETONATION_OUTPUT_DIR)
        if output_dir.exists():
            for f in sorted(output_dir.glob('*.json'), key=os.path.getmtime, reverse=True)[:10]:
                try:
                    with open(f) as fp:
                        data = json.load(fp)
                        if 'analysis' in data:
                            detonations.append(data['analysis'])
                except Exception:
                    pass
    except Exception:
        pass

    # Get learning stats
    learning_stats = get_learning_stats()

    return render_template('dashboard.html',
                           stats=stats,
                           stats_week=stats_week,
                           stats_today=stats_today,
                           campaigns=alert_campaigns[:5],
                           feedback_stats=feedback_stats,
                           unique_users=unique_users,
                           detonations=detonations,
                           learning_stats=learning_stats)


@app.route('/submissions')
@login_required
def submissions():
    """View all checked emails."""
    page = request.args.get('page', 1, type=int)
    verdict = request.args.get('verdict')
    department = request.args.get('department')

    limit = 50
    offset = (page - 1) * limit

    items = get_submissions(limit=limit, offset=offset, verdict=verdict, department=department)

    # Parse signals JSON for display
    for item in items:
        if item.get('signals'):
            try:
                item['signals'] = json.loads(item['signals'])
            except (json.JSONDecodeError, TypeError):
                item['signals'] = []

    return render_template('submissions.html',
                           submissions=items,
                           page=page,
                           verdict=verdict,
                           department=department)


@app.route('/campaigns')
@login_required
def campaigns():
    """View campaign alerts."""
    all_campaigns = get_active_campaigns()

    # Add alert levels
    for campaign in all_campaigns:
        campaign['alert_level'] = get_campaign_alert_level(campaign['id'])
        if campaign.get('indicators'):
            try:
                campaign['indicators'] = json.loads(campaign['indicators'])
            except (json.JSONDecodeError, TypeError):
                campaign['indicators'] = {}

    # Sort by alert level (critical first)
    level_order = {'critical': 0, 'elevated': 1, 'warning': 2, 'normal': 3}
    all_campaigns.sort(key=lambda c: level_order.get(c['alert_level'], 4))

    return render_template('campaigns.html', campaigns=all_campaigns)


@app.route('/accuracy')
@login_required
def accuracy():
    """View accuracy metrics and feedback."""
    feedback_stats = get_feedback_stats(days=30)
    pending = get_pending_feedback()
    whitelist = get_whitelist()
    blacklist = get_blacklist()

    return render_template('accuracy.html',
                           stats=feedback_stats,
                           pending=pending,
                           whitelist=whitelist,
                           blacklist=blacklist)


# =============================================================================
# API Routes
# =============================================================================

@app.route('/api/check', methods=['POST'])
def api_check():
    """
    Main API endpoint for checking emails.

    Expects JSON:
    {
        "headers": "raw email headers",
        "body_html": "email body HTML",
        "sender": "sender@example.com",
        "subject": "Email subject",
        "submitted_by": "user@company.com",  # optional
        "method": "addon" or "forward"  # optional
    }

    Returns:
    {
        "verdict": "phishing" | "suspicious" | "safe",
        "confidence": 0-100,
        "signals": [...],
        "submission_id": "uuid"
    }
    """
    try:
        data = request.get_json(silent=True)

        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400

        headers = data.get('headers', '')
        body_html = data.get('body_html', '')
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        submitted_by = data.get('submitted_by', '')
        method = data.get('method', 'addon')

        # Input size validation (max 1MB per field, 2MB total)
        MAX_FIELD_SIZE = 1_000_000
        for field_name, field_val in [('headers', headers), ('body_html', body_html)]:
            if isinstance(field_val, str) and len(field_val) > MAX_FIELD_SIZE:
                return jsonify({'error': f'{field_name} exceeds maximum size (1MB)'}), 413

        if not sender:
            return jsonify({'error': 'Sender is required'}), 400

        # Analyze the email
        result = analyze_email(headers, body_html, sender, subject)

        # Get user department from Graph API if available
        department = None
        if submitted_by:
            graph = get_graph_client()
            if graph:
                department = graph.get_user_department(submitted_by)

        # Check for campaign
        campaign, is_new = find_or_create_campaign(
            result['fingerprint'],
            result['sender_domain'],
            subject
        )
        campaign_id = campaign['id'] if campaign else None

        # Check if this triggers a CISO alert
        if campaign and config.ENABLE_CISO_ALERTS:
            try:
                indicators = json.loads(campaign.get('indicators', '{}')) if isinstance(campaign.get('indicators'), str) else campaign.get('indicators', {})
                check_campaign_alerts(
                    campaign_id=campaign['id'],
                    campaign_name=campaign.get('name', 'Unknown'),
                    user_count=campaign.get('user_count', 0),
                    indicators=indicators
                )
            except Exception as e:
                logger.warning(f'Failed to check campaign alerts: {e}')

        # Store submission
        submission_id = create_submission(
            fingerprint=result['fingerprint'],
            submitted_by=submitted_by,
            submission_method=method,
            department=department,
            original_sender=sender,
            sender_domain=result['sender_domain'],
            subject=subject,
            headers=headers,
            body_html=body_html,
            verdict=result['verdict'],
            confidence=result['confidence'],
            signals=result['signals'],
            campaign_id=campaign_id
        )

        # Return response
        return jsonify({
            'verdict': result['verdict'],
            'confidence': result['confidence'],
            'signals': result['signals'],
            'submission_id': submission_id
        })

    except Exception as e:
        logger.exception('Error in /api/check')
        return jsonify({'error': str(e)}), 500


@app.route('/api/feedback/<submission_id>', methods=['POST'])
def api_feedback(submission_id):
    """
    Submit feedback on a verdict.

    Expects JSON:
    {
        "user_email": "user@company.com",
        "user_says": "correct" | "false_positive" | "false_negative",
        "reason": "optional reason",
        "notes": "optional notes"
    }
    """
    try:
        data = request.get_json()

        submission = get_submission(submission_id)
        if not submission:
            return jsonify({'error': 'Submission not found'}), 404

        feedback_id = create_feedback(
            submission_id=submission_id,
            user_email=data.get('user_email', ''),
            original_verdict=submission['verdict'],
            user_says=data.get('user_says', 'correct'),
            reason=data.get('reason'),
            notes=data.get('notes')
        )

        # Check for auto-whitelist if this was a false positive
        auto_whitelisted = False
        if data.get('user_says') == 'false_positive' and submission.get('sender_domain'):
            auto_whitelisted = check_auto_whitelist(submission['sender_domain'])

        return jsonify({
            'feedback_id': feedback_id,
            'status': 'received',
            'auto_whitelisted': auto_whitelisted
        })

    except Exception as e:
        logger.exception('Error in feedback')
        return jsonify({'error': str(e)}), 500


@app.route('/feedback/<submission_id>')
def feedback_page(submission_id):
    """Handle feedback links from emails."""
    correct = request.args.get('correct')
    submission = get_submission(submission_id)

    if not submission:
        return "Submission not found", 404

    if correct == 'yes':
        create_feedback(submission_id, '', submission['verdict'], 'correct')
        return render_template('feedback_thanks.html', message="Thank you! Your feedback helps improve our accuracy.")
    elif correct == 'no':
        return render_template('feedback_form.html', submission=submission)

    return redirect(url_for('dashboard'))


@app.route('/feedback/<submission_id>/submit', methods=['POST'])
def feedback_submit(submission_id):
    """Handle feedback form submission."""
    submission = get_submission(submission_id)
    if not submission:
        return "Submission not found", 404

    user_says = 'false_positive' if submission['verdict'] in ('phishing', 'suspicious') else 'false_negative'
    reason = request.form.get('reason', '')
    notes = request.form.get('notes', '')

    create_feedback(submission_id, '', submission['verdict'], user_says, reason, notes)

    # Check for auto-whitelist if this was a false positive
    auto_whitelisted = False
    if user_says == 'false_positive' and submission.get('sender_domain'):
        auto_whitelisted = check_auto_whitelist(submission['sender_domain'])

    message = "Thank you for your feedback! Our team will review this."
    if auto_whitelisted:
        message = f"Thank you! The domain {submission['sender_domain']} has been automatically whitelisted based on multiple reports."

    return render_template('feedback_thanks.html', message=message)


# =============================================================================
# Whitelist/Blacklist Management
# =============================================================================

@app.route('/api/whitelist', methods=['POST'])
@login_required
def api_add_whitelist():
    """Add to whitelist."""
    data = request.get_json()
    entry_id = add_to_whitelist(
        type_=data.get('type', 'domain'),
        value=data.get('value'),
        reason=data.get('reason', ''),
        added_by=session.get('username', 'admin')
    )
    return jsonify({'id': entry_id})


@app.route('/api/whitelist/<entry_id>', methods=['DELETE'])
@login_required
def api_remove_whitelist(entry_id):
    """Remove from whitelist."""
    remove_from_whitelist(entry_id)
    return jsonify({'status': 'removed'})


@app.route('/api/blacklist', methods=['POST'])
@login_required
def api_add_blacklist():
    """Add to blacklist."""
    data = request.get_json()
    entry_id = add_to_blacklist(
        type_=data.get('type', 'domain'),
        value=data.get('value'),
        reason=data.get('reason', ''),
        added_by=session.get('username', 'admin')
    )
    return jsonify({'id': entry_id})


@app.route('/api/blacklist/<entry_id>', methods=['DELETE'])
@login_required
def api_remove_blacklist(entry_id):
    """Remove from blacklist."""
    remove_from_blacklist(entry_id)
    return jsonify({'status': 'removed'})


# =============================================================================
# Stats API (for charts)
# =============================================================================

@app.route('/api/stats')
@login_required
def api_stats():
    """Get stats for dashboard charts."""
    days = request.args.get('days', 30, type=int)
    stats = get_submission_stats(days=days)
    return jsonify(stats)


@app.route('/api/stats/departments')
@login_required
def api_department_stats():
    """Get department breakdown from Graph API."""
    graph = get_graph_client()
    if not graph:
        return jsonify({'error': 'Graph API not configured'}), 503

    departments = graph.get_all_departments()
    return jsonify({'departments': departments})


# =============================================================================
# URL Detonation API
# =============================================================================

@app.route('/api/detonate', methods=['POST'])
@login_required
def api_detonate_url():
    """
    Manually detonate a URL via urlscan.io.

    Request body: {"url": "https://suspicious-site.com"}
    """
    if not config.URLSCAN_API_KEY:
        return jsonify({'error': 'URL detonation not configured - set URLSCAN_API_KEY'}), 503

    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url parameter'}), 400

    url = data['url']
    if not url.startswith('http'):
        return jsonify({'error': 'Invalid URL - must start with http:// or https://'}), 400

    try:
        from urlscan_detonator import URLScanDetonator
        detonator = URLScanDetonator(
            api_key=config.URLSCAN_API_KEY,
            output_dir=config.DETONATION_OUTPUT_DIR
        )
        result = detonator.detonate(url)
        return jsonify(result)
    except Exception as e:
        logger.error(f"URL detonation failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detonations')
@login_required
def api_list_detonations():
    """List recent URL detonation reports."""
    import os
    from pathlib import Path

    output_dir = Path(config.DETONATION_OUTPUT_DIR)
    if not output_dir.exists():
        return jsonify({'detonations': []})

    reports = []
    for f in sorted(output_dir.glob('*.json'), key=os.path.getmtime, reverse=True)[:50]:
        try:
            with open(f) as fp:
                data = json.load(fp)
                if 'analysis' in data:
                    reports.append(data['analysis'])
        except Exception:
            pass

    return jsonify({'detonations': reports})


# =============================================================================
# Outlook Add-in
# =============================================================================

@app.route('/addon/<path:filename>')
def serve_addon(filename):
    """Serve Outlook add-in files."""
    addon_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'addon')
    return send_from_directory(addon_dir, filename)


@app.route('/addon/manifest.xml')
def serve_manifest():
    """Serve add-in manifest with correct content type."""
    addon_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'addon')
    return send_from_directory(addon_dir, 'manifest.xml', mimetype='application/xml')


# =============================================================================
# Health Check
# =============================================================================

@app.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok'})


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    app.run(debug=config.DEBUG, host='0.0.0.0', port=5000)
