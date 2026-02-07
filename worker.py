#!/usr/bin/env python3
"""
PhishCheck Email Worker

Polls the phishing@forzon.ca inbox for forwarded emails,
analyzes them, and sends verdict replies.

Run as: python3 worker.py
Or via systemd service.
"""

import time
import logging
import signal
import sys

from email_handler import process_inbox

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('phishcheck-worker')

# Polling interval in seconds
POLL_INTERVAL = 10

# Graceful shutdown flag
running = True


def signal_handler(signum, frame):
    global running
    logger.info('Shutdown signal received, stopping...')
    running = False


def main():
    global running

    # Handle shutdown signals
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info('PhishCheck email worker starting...')
    logger.info(f'Polling interval: {POLL_INTERVAL} seconds')

    while running:
        try:
            processed = process_inbox()
            if processed > 0:
                logger.info(f'Processed {processed} email(s)')
        except Exception as e:
            logger.error(f'Error processing inbox: {e}')

        # Sleep in small increments to allow quick shutdown
        for _ in range(POLL_INTERVAL):
            if not running:
                break
            time.sleep(1)

    logger.info('PhishCheck email worker stopped.')


if __name__ == '__main__':
    main()
