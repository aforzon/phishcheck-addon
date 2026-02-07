/**
 * PhishCheck Outlook Add-in
 *
 * Calls the PhishCheck API to analyze the currently selected email
 * and displays the verdict to the user.
 */

// API endpoint - change this to your server URL
const API_BASE = 'https://phishcheck.forzon.ca';

// Store submission ID for feedback
let currentSubmissionId = null;
let currentItem = null;

// Initialize when Office.js is ready
Office.onReady((info) => {
    if (info.host === Office.HostType.Outlook) {
        analyzeEmail();
    }
});

/**
 * Get the current email item and analyze it
 */
async function analyzeEmail() {
    showLoading();

    try {
        const item = Office.context.mailbox.item;
        currentItem = item;

        // Get email data
        const emailData = await getEmailData(item);

        // Send to API
        const result = await checkEmail(emailData);

        // Display result
        showResult(result);

    } catch (error) {
        console.error('Analysis error:', error);
        showError(error.message || 'Failed to analyze email');
    }
}

/**
 * Extract email data from Outlook item
 */
function getEmailData(item) {
    return new Promise((resolve, reject) => {
        // Get sender
        const sender = item.from ? item.from.emailAddress : '';
        const subject = item.subject || '';

        // Get headers (requires ReadItem permission)
        item.getAllInternetHeadersAsync((headersResult) => {
            let headers = '';
            if (headersResult.status === Office.AsyncResultStatus.Succeeded) {
                headers = headersResult.value;
            }

            // Get body
            item.body.getAsync(Office.CoercionType.Html, (bodyResult) => {
                let bodyHtml = '';
                if (bodyResult.status === Office.AsyncResultStatus.Succeeded) {
                    bodyHtml = bodyResult.value;
                }

                // Get current user email
                const userEmail = Office.context.mailbox.userProfile.emailAddress || '';

                resolve({
                    headers: headers,
                    body_html: bodyHtml,
                    sender: sender,
                    subject: subject,
                    submitted_by: userEmail,
                    method: 'addon'
                });
            });
        });
    });
}

/**
 * Send email data to PhishCheck API
 */
async function checkEmail(emailData) {
    const response = await fetch(`${API_BASE}/api/check`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(emailData)
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'API request failed');
    }

    return response.json();
}

/**
 * Display the analysis result
 */
function showResult(result) {
    currentSubmissionId = result.submission_id;

    // Hide loading, show result
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('result').classList.remove('hidden');

    // Set verdict styling
    const verdictBox = document.getElementById('verdictBox');
    const verdictIcon = document.getElementById('verdictIcon');
    const verdictText = document.getElementById('verdictText');
    const confidence = document.getElementById('confidence');

    switch (result.verdict) {
        case 'phishing':
            verdictBox.className = 'rounded-lg p-6 text-center mb-4 bg-red-100';
            verdictIcon.textContent = '🔴';
            verdictText.textContent = 'YES - PHISHING';
            verdictText.className = 'text-2xl font-bold text-red-700';
            break;
        case 'suspicious':
            verdictBox.className = 'rounded-lg p-6 text-center mb-4 bg-yellow-100';
            verdictIcon.textContent = '🟡';
            verdictText.textContent = 'SUSPICIOUS';
            verdictText.className = 'text-2xl font-bold text-yellow-700';
            break;
        default:
            verdictBox.className = 'rounded-lg p-6 text-center mb-4 bg-green-100';
            verdictIcon.textContent = '🟢';
            verdictText.textContent = 'LIKELY SAFE';
            verdictText.className = 'text-2xl font-bold text-green-700';
    }

    // For safe emails, show confidence it's safe (inverted)
    const displayConfidence = result.verdict === 'safe'
        ? (100 - result.confidence)
        : result.confidence;

    // Make the label explicit about what confidence means
    let confidenceLabel;
    if (result.verdict === 'phishing') {
        confidenceLabel = `${displayConfidence}% confident this is phishing`;
    } else if (result.verdict === 'suspicious') {
        confidenceLabel = `${displayConfidence}% risk level`;
    } else {
        confidenceLabel = `${displayConfidence}% confident this is safe`;
    }
    confidence.textContent = confidenceLabel;
    confidence.className = 'text-lg mt-1 text-gray-600';

    // Display signals
    const signalsList = document.getElementById('signals');
    signalsList.innerHTML = '';

    if (result.signals && result.signals.length > 0) {
        result.signals.forEach(signal => {
            const li = document.createElement('li');
            li.className = 'flex items-start';
            li.innerHTML = `
                <span class="text-gray-400 mr-2">•</span>
                <span class="text-gray-700">${escapeHtml(signal.description)}</span>
            `;
            signalsList.appendChild(li);
        });
    } else {
        const li = document.createElement('li');
        li.className = 'text-gray-500';
        li.textContent = 'No specific signals detected';
        signalsList.appendChild(li);
    }
}

/**
 * Show loading state
 */
function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('result').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    document.getElementById('feedbackThanks').classList.add('hidden');
}

/**
 * Show error state
 */
function showError(message) {
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('result').classList.add('hidden');
    document.getElementById('error').classList.remove('hidden');
    document.getElementById('errorMessage').textContent = message;
}

/**
 * Delete the current email
 */
function deleteEmail() {
    if (currentItem && currentItem.itemId) {
        // Move to deleted items
        Office.context.mailbox.item.move(
            Office.context.mailbox.deletedItemsFolder,
            (result) => {
                if (result.status === Office.AsyncResultStatus.Succeeded) {
                    // Close the task pane after deletion
                    Office.context.ui.closeContainer();
                } else {
                    alert('Could not delete email. Please delete manually.');
                }
            }
        );
    }
}

/**
 * Report the email (placeholder - could integrate with IT ticketing)
 */
function reportEmail() {
    // In production, this could create a ticket or notify IT
    alert('Email has been reported to the security team.');
}

/**
 * Send feedback on the verdict
 */
async function sendFeedback(response) {
    if (!currentSubmissionId) return;

    const userEmail = Office.context.mailbox.userProfile.emailAddress || '';

    try {
        await fetch(`${API_BASE}/api/feedback/${currentSubmissionId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_email: userEmail,
                user_says: response === 'correct' ? 'correct' : 'false_positive'
            })
        });

        // Show thanks
        document.getElementById('result').classList.add('hidden');
        document.getElementById('feedbackThanks').classList.remove('hidden');

    } catch (error) {
        console.error('Feedback error:', error);
        alert('Could not submit feedback. Please try again.');
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
