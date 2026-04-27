"""Gmail watch management — register and stop Pub/Sub push notifications."""

import logging

logger = logging.getLogger(__name__)


def start_watch(service, topic_name: str) -> dict:
    """Register a Pub/Sub push watch for the user's inbox.

    Returns the Gmail API response containing historyId and expiration.
    Watches expire after 7 days; renew via Cloud Scheduler every 6 days.
    """
    response = (
        service.users()
        .watch(
            userId="me",
            body={
                "labelIds": ["INBOX"],
                "topicName": topic_name,
            },
        )
        .execute()
    )
    logger.info(
        "Watch registered: historyId=%s expiration=%s",
        response.get("historyId"),
        response.get("expiration"),
    )
    return response


def stop_watch(service) -> None:
    """Deregister the Pub/Sub push watch for the user's inbox."""
    service.users().stop(userId="me").execute()
    logger.info("Watch stopped")
