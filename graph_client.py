"""
Microsoft Graph API Client

Handles:
- Reading the phishing@forzon.ca mailbox
- Sending reply emails with verdicts
- Looking up user departments from Azure AD
"""

import requests
from datetime import datetime, timedelta
from html import escape as html_escape
import logging

logger = logging.getLogger(__name__)

# MSAL is optional - only needed when Graph API is configured
try:
    import msal
    MSAL_AVAILABLE = True
except ImportError:
    MSAL_AVAILABLE = False
    logger.warning('msal not installed - Graph API features disabled')


class GraphClient:
    def __init__(self, tenant_id, client_id, client_secret):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = 'https://graph.microsoft.com/v1.0'
        self._token = None
        self._token_expires = None

    def _get_token(self):
        """Get or refresh access token using client credentials flow."""
        if not MSAL_AVAILABLE:
            raise Exception('msal library not installed')

        if self._token and self._token_expires and datetime.now() < self._token_expires:
            return self._token

        authority = f'https://login.microsoftonline.com/{self.tenant_id}'
        app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=authority,
            client_credential=self.client_secret
        )

        result = app.acquire_token_for_client(
            scopes=['https://graph.microsoft.com/.default']
        )

        if 'access_token' in result:
            self._token = result['access_token']
            # Token typically valid for 1 hour, refresh 5 min early
            self._token_expires = datetime.now() + timedelta(minutes=55)
            return self._token
        else:
            error = result.get('error_description', 'Unknown error')
            logger.error(f'Failed to get token: {error}')
            raise Exception(f'Failed to acquire token: {error}')

    def _request(self, method, endpoint, **kwargs):
        """Make authenticated request to Graph API."""
        token = self._get_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        headers.update(kwargs.pop('headers', {}))

        url = f'{self.base_url}{endpoint}'
        response = requests.request(method, url, headers=headers, **kwargs)

        if response.status_code == 401:
            # Token might be expired, clear and retry
            self._token = None
            self._token_expires = None
            token = self._get_token()
            headers['Authorization'] = f'Bearer {token}'
            response = requests.request(method, url, headers=headers, **kwargs)

        return response

    # =========================================================================
    # USER DEPARTMENT LOOKUP - Key for dashboard stats
    # =========================================================================

    def get_user_department(self, email):
        """
        Get user's department from Azure AD.

        Args:
            email: User's email address

        Returns:
            Department name (str) or None if not found

        Requires: User.Read.All permission
        """
        try:
            endpoint = f'/users/{email}?$select=mail,department,displayName,jobTitle'
            response = self._request('GET', endpoint)

            if response.status_code == 200:
                data = response.json()
                department = data.get('department')
                if department:
                    logger.info(f'Found department for {email}: {department}')
                    return department
                else:
                    logger.info(f'No department set for {email}')
                    return None
            elif response.status_code == 404:
                logger.warning(f'User not found: {email}')
                return None
            else:
                logger.error(f'Error getting user {email}: {response.status_code} - {response.text}')
                return None

        except Exception as e:
            logger.error(f'Exception getting department for {email}: {e}')
            return None

    def get_user_details(self, email):
        """
        Get full user details from Azure AD.

        Returns dict with: mail, department, displayName, jobTitle, officeLocation
        """
        try:
            endpoint = f'/users/{email}?$select=mail,department,displayName,jobTitle,officeLocation,companyName'
            response = self._request('GET', endpoint)

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f'Error getting user details: {response.status_code}')
                return None

        except Exception as e:
            logger.error(f'Exception getting user details: {e}')
            return None

    def get_all_departments(self):
        """
        Get list of all departments in the organization.

        Useful for dashboard filtering and stats.

        Returns list of unique department names.
        """
        try:
            departments = set()
            endpoint = '/users?$select=department&$top=999'

            while endpoint:
                response = self._request('GET', endpoint)
                if response.status_code != 200:
                    break

                data = response.json()
                for user in data.get('value', []):
                    dept = user.get('department')
                    if dept:
                        departments.add(dept)

                # Handle pagination
                endpoint = data.get('@odata.nextLink', '').replace(self.base_url, '')
                if not endpoint:
                    break

            return sorted(list(departments))

        except Exception as e:
            logger.error(f'Exception getting departments: {e}')
            return []

    def get_department_user_count(self, department):
        """Get count of users in a specific department."""
        try:
            endpoint = f"/users?$filter=department eq '{department}'&$count=true"
            headers = {'ConsistencyLevel': 'eventual'}
            response = self._request('GET', endpoint, headers=headers)

            if response.status_code == 200:
                return response.json().get('@odata.count', 0)
            return 0

        except Exception as e:
            logger.error(f'Exception getting department count: {e}')
            return 0

    # =========================================================================
    # MAILBOX OPERATIONS - For the forward-to-check method
    # =========================================================================

    def get_messages(self, mailbox, folder='inbox', top=50, unread_only=True):
        """
        Get messages from the phishing mailbox.

        Args:
            mailbox: Email address of shared mailbox (phishing@forzon.ca)
            folder: Folder to read from (default: inbox)
            top: Max messages to return
            unread_only: Only return unread messages

        Returns:
            List of message objects
        """
        try:
            endpoint = f'/users/{mailbox}/mailFolders/{folder}/messages'
            params = {
                '$top': top,
                '$orderby': 'receivedDateTime desc',
                '$select': 'id,subject,from,receivedDateTime,isRead,body,internetMessageHeaders'
            }
            if unread_only:
                params['$filter'] = 'isRead eq false'

            response = self._request('GET', endpoint, params=params)

            if response.status_code == 200:
                return response.json().get('value', [])
            else:
                logger.error(f'Error getting messages: {response.status_code} - {response.text}')
                return []

        except Exception as e:
            logger.error(f'Exception getting messages: {e}')
            return []

    def get_message(self, mailbox, message_id):
        """Get a single message with full details including headers."""
        try:
            endpoint = f'/users/{mailbox}/messages/{message_id}'
            params = {
                '$select': 'id,subject,from,toRecipients,receivedDateTime,body,internetMessageHeaders'
            }
            response = self._request('GET', endpoint, params=params)

            if response.status_code == 200:
                return response.json()
            return None

        except Exception as e:
            logger.error(f'Exception getting message: {e}')
            return None

    def mark_as_read(self, mailbox, message_id):
        """Mark a message as read."""
        try:
            endpoint = f'/users/{mailbox}/messages/{message_id}'
            data = {'isRead': True}
            response = self._request('PATCH', endpoint, json=data)
            return response.status_code == 200

        except Exception as e:
            logger.error(f'Exception marking message read: {e}')
            return False

    def send_reply(self, mailbox, message_id, reply_body):
        """
        Send a reply to a message from the phishing mailbox.

        Args:
            mailbox: The phishing mailbox address
            message_id: ID of original message to reply to
            reply_body: HTML body of the reply
        """
        try:
            endpoint = f'/users/{mailbox}/messages/{message_id}/reply'
            data = {
                'message': {
                    'body': {
                        'contentType': 'HTML',
                        'content': reply_body
                    }
                }
            }
            response = self._request('POST', endpoint, json=data)

            if response.status_code in [200, 202]:
                logger.info(f'Reply sent successfully for message {message_id}')
                return True
            else:
                logger.error(f'Error sending reply: {response.status_code} - {response.text}')
                return False

        except Exception as e:
            logger.error(f'Exception sending reply: {e}')
            return False

    def send_email(self, mailbox, to_email, subject, body_html):
        """
        Send a new email from the phishing mailbox.

        Args:
            mailbox: Sender mailbox
            to_email: Recipient email
            subject: Email subject
            body_html: HTML body
        """
        try:
            endpoint = f'/users/{mailbox}/sendMail'
            data = {
                'message': {
                    'subject': subject,
                    'body': {
                        'contentType': 'HTML',
                        'content': body_html
                    },
                    'toRecipients': [
                        {'emailAddress': {'address': to_email}}
                    ]
                },
                'saveToSentItems': True
            }
            response = self._request('POST', endpoint, json=data)
            return response.status_code == 202

        except Exception as e:
            logger.error(f'Exception sending email: {e}')
            return False

    # =========================================================================
    # ORGANIZATION INFO
    # =========================================================================

    def get_org_info(self):
        """Get basic organization info."""
        try:
            response = self._request('GET', '/organization')
            if response.status_code == 200:
                orgs = response.json().get('value', [])
                if orgs:
                    return orgs[0]
            return None

        except Exception as e:
            logger.error(f'Exception getting org info: {e}')
            return None

    def get_user_count(self):
        """Get total user count in the organization."""
        try:
            endpoint = '/users?$count=true&$top=1'
            headers = {'ConsistencyLevel': 'eventual'}
            response = self._request('GET', endpoint, headers=headers)

            if response.status_code == 200:
                return response.json().get('@odata.count', 0)
            return 0

        except Exception as e:
            logger.error(f'Exception getting user count: {e}')
            return 0


# Singleton instance - initialized from config
_client = None


def get_graph_client():
    """Get the singleton Graph client instance."""
    global _client
    if _client is None:
        if not MSAL_AVAILABLE:
            logger.warning('Graph API not available - msal library not installed')
            return None
        from config import AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
        if AZURE_TENANT_ID and AZURE_CLIENT_ID and AZURE_CLIENT_SECRET:
            _client = GraphClient(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
        else:
            logger.warning('Graph API not configured - Azure credentials missing')
            return None
    return _client


def format_verdict_email(verdict, confidence, signals, submission_id):
    """
    Format the verdict as an HTML email reply.

    Args:
        verdict: 'phishing', 'suspicious', or 'safe'
        confidence: Confidence score (0-100)
        signals: List of triggered signals with descriptions
        submission_id: For feedback links
    """
    from config import PHISHING_MAILBOX

    verdict_emoji = {
        'phishing': '🔴',
        'suspicious': '🟡',
        'safe': '🟢'
    }

    verdict_text = {
        'phishing': 'YES - THIS IS PHISHING',
        'suspicious': 'SUSPICIOUS - BE CAREFUL',
        'safe': 'LIKELY SAFE'
    }

    verdict_action = {
        'phishing': 'Delete this email immediately.',
        'suspicious': 'Verify the sender through another channel before taking any action.',
        'safe': 'This email appears legitimate, but always stay vigilant.'
    }

    emoji = verdict_emoji.get(verdict, '❓')
    text = verdict_text.get(verdict, 'UNKNOWN')
    action = verdict_action.get(verdict, '')

    # Format signals as bullet points
    signal_html = ''
    if signals:
        signal_html = '<ul style="margin: 10px 0; padding-left: 20px;">'
        for signal in signals:
            signal_html += f'<li>{html_escape(signal["description"])}</li>'
        signal_html += '</ul>'

    # Build feedback URLs (would need actual domain)
    base_url = 'https://phishcheck.forzon.ca'
    feedback_yes = f'{base_url}/feedback/{submission_id}?correct=yes'
    feedback_no = f'{base_url}/feedback/{submission_id}?correct=no'

    html = f'''
    <div style="font-family: Arial, sans-serif; max-width: 600px;">
        <hr style="border: 2px solid #333;">
        <h2 style="text-align: center; font-size: 24px; margin: 20px 0;">
            {emoji} {text}
        </h2>
        <p style="text-align: center; font-size: 18px;">
            <strong>Confidence: {confidence}%</strong>
        </p>
        <div style="margin: 20px 0;">
            <strong>Why:</strong>
            {signal_html}
        </div>
        <p style="background: #f5f5f5; padding: 15px; border-radius: 5px;">
            <strong>Action:</strong> {action}
        </p>
        <hr style="border: 1px solid #ccc; margin: 30px 0;">
        <p style="text-align: center;">
            <strong>Was this verdict correct?</strong><br><br>
            👍 <a href="{feedback_yes}">Yes, correct</a>&nbsp;&nbsp;&nbsp;
            👎 <a href="{feedback_no}">No, incorrect</a>
        </p>
        <hr style="border: 2px solid #333;">
    </div>
    '''

    return html
