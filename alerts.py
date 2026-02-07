"""
Campaign Alert System

Monitors for coordinated phishing attacks and sends
real-time alerts to the CISO when thresholds are exceeded.
"""

import logging
from datetime import datetime
from html import escape as html_escape
from models import get_db, get_campaign_alert_level
from graph_client import get_graph_client
import config

logger = logging.getLogger(__name__)

# Track which campaigns have already been alerted
_alerted_campaigns = {}


def check_campaign_alerts(campaign_id, campaign_name, user_count, indicators):
    """
    Check if a campaign needs to trigger a CISO alert.

    Called after each new submission is linked to a campaign.
    """
    alert_level = get_campaign_alert_level(campaign_id)

    if alert_level == 'normal':
        return

    # Check if we already alerted for this level
    prev_level = _alerted_campaigns.get(campaign_id)
    if prev_level == alert_level:
        return  # Already alerted at this level

    # Escalation: only alert if level increased
    level_priority = {'warning': 1, 'elevated': 2, 'critical': 3}
    if prev_level and level_priority.get(prev_level, 0) >= level_priority.get(alert_level, 0):
        return

    # Send alert
    send_ciso_alert(campaign_id, campaign_name, alert_level, user_count, indicators)

    # Track that we alerted
    _alerted_campaigns[campaign_id] = alert_level


def send_ciso_alert(campaign_id, campaign_name, alert_level, user_count, indicators):
    """
    Send an email alert to the CISO about a phishing campaign.
    """
    # Get CISO email from config (or use a default)
    ciso_email = getattr(config, 'CISO_EMAIL', None)
    if not ciso_email:
        logger.warning('CISO_EMAIL not configured, skipping alert')
        return

    graph = get_graph_client()
    if not graph:
        logger.warning('Graph API not configured, cannot send CISO alert')
        return

    # Build alert email
    subject = f"[{alert_level.upper()}] Phishing Campaign Alert - {user_count} users affected"

    # Escape user-controlled values to prevent HTML injection
    safe_campaign_name = html_escape(str(campaign_name))
    safe_sender_domain = html_escape(str(indicators.get('sender_domain', 'Unknown')))
    safe_subject_pattern = html_escape(str(indicators.get('subject_pattern', 'Unknown')))

    # Get department breakdown
    dept_breakdown = get_department_breakdown(campaign_id)
    dept_html = ''.join([f'<li>{html_escape(str(d["department"]))}: {d["count"]} users</li>' for d in dept_breakdown])

    # Build email body
    body_html = f'''
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: {'#DC2626' if alert_level == 'critical' else '#F59E0B' if alert_level == 'elevated' else '#EAB308'}; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">
                {'🚨' if alert_level == 'critical' else '⚠️'} PHISHING CAMPAIGN DETECTED
            </h1>
            <p style="margin: 10px 0 0 0; font-size: 18px;">Alert Level: {alert_level.upper()}</p>
        </div>

        <div style="padding: 20px; background: #f9fafb;">
            <h2 style="color: #111827; margin-top: 0;">Campaign Details</h2>

            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold; width: 140px;">Users Affected:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-size: 18px; color: #DC2626;">{user_count}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">Campaign:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">{safe_campaign_name}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">Sender Domain:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">
                        <code style="background: #fee2e2; padding: 2px 6px; border-radius: 4px;">
                            {safe_sender_domain}
                        </code>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">Subject Pattern:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">{safe_subject_pattern}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb; font-weight: bold;">First Seen:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">{datetime.now().strftime('%Y-%m-%d %H:%M')} UTC</td>
                </tr>
            </table>

            <h3 style="color: #111827; margin-top: 20px;">Departments Targeted</h3>
            <ul style="margin: 0; padding-left: 20px;">
                {dept_html if dept_html else '<li>Data not available</li>'}
            </ul>

            <div style="margin-top: 20px; padding: 15px; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;">
                <h3 style="margin: 0 0 10px 0; color: #111827;">Recommended Actions</h3>
                <ol style="margin: 0; padding-left: 20px;">
                    <li>Review the campaign in the <a href="https://phishcheck.forzon.ca/campaigns">PhishCheck Dashboard</a></li>
                    <li>Consider blocking the sender domain: <code>{safe_sender_domain}</code></li>
                    <li>Send a company-wide alert if attack is widespread</li>
                    <li>Export IOCs for your security tools</li>
                </ol>
            </div>

            <div style="margin-top: 20px; text-align: center;">
                <a href="https://phishcheck.forzon.ca/campaigns"
                   style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">
                    View Dashboard
                </a>
            </div>
        </div>

        <div style="padding: 15px; background: #e5e7eb; text-align: center; font-size: 12px; color: #6b7280;">
            This alert was automatically generated by PhishCheck.<br>
            Alert thresholds: Warning (10+ users/hour), Elevated (30+ users/2 hours), Critical (60+ users/4 hours)
        </div>
    </div>
    '''

    try:
        success = graph.send_email(
            mailbox=config.PHISHING_MAILBOX,
            to_email=ciso_email,
            subject=subject,
            body_html=body_html
        )
        if success:
            logger.info(f'CISO alert sent for campaign {campaign_id} at level {alert_level}')
        else:
            logger.error(f'Failed to send CISO alert for campaign {campaign_id}')
    except Exception as e:
        logger.exception(f'Error sending CISO alert: {e}')


def get_department_breakdown(campaign_id):
    """Get department breakdown for a campaign."""
    with get_db() as conn:
        rows = conn.execute('''
            SELECT department, COUNT(*) as count
            FROM submissions
            WHERE campaign_id = ? AND department IS NOT NULL
            GROUP BY department
            ORDER BY count DESC
            LIMIT 10
        ''', (campaign_id,)).fetchall()
        return [dict(row) for row in rows]


def send_test_alert(ciso_email):
    """
    Send a test alert to verify email configuration.

    Usage: python -c "from alerts import send_test_alert; send_test_alert('ciso@forzon.ca')"
    """
    graph = get_graph_client()
    if not graph:
        print('Graph API not configured')
        return False

    body_html = '''
    <div style="font-family: Arial, sans-serif; padding: 20px;">
        <h2>PhishCheck Test Alert</h2>
        <p>This is a test alert to verify your CISO alert configuration is working correctly.</p>
        <p>If you received this email, alerts are configured properly!</p>
        <p><a href="https://phishcheck.forzon.ca">Go to Dashboard</a></p>
    </div>
    '''

    try:
        success = graph.send_email(
            mailbox=config.PHISHING_MAILBOX,
            to_email=ciso_email,
            subject='[TEST] PhishCheck Alert Configuration Test',
            body_html=body_html
        )
        print('Test alert sent!' if success else 'Failed to send test alert')
        return success
    except Exception as e:
        print(f'Error: {e}')
        return False
