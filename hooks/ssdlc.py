# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""SSDLC (Secure Software Development Lifecycle) Security Event Logging.

Implements structured security event logging per Canonical's SSDLC standard (v1.1).
Covers system lifecycle events (SYS) and user management (USER) event categories.
"""

from datetime import datetime, timezone
from enum import Enum
from logging import getLogger

logger = getLogger(__name__)

APPID_PREFIX = "charm.userdir-ldap"


class SSDLCEvent(str, Enum):
    """SSDLC security event types."""

    # System events [SYS]
    SYS_RESTART = "sys_restart"

    # User events [USER]
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"


_EVENT_LEVELS = {
    SSDLCEvent.SYS_RESTART: "WARN",
    SSDLCEvent.USER_CREATED: "WARN",
    SSDLCEvent.USER_UPDATED: "WARN",
}

_EVENT_DESCRIPTIONS = {
    SSDLCEvent.SYS_RESTART: "Service %s restarted",
    SSDLCEvent.USER_CREATED: "User created: %s",
    SSDLCEvent.USER_UPDATED: "User updated: %s",
}


def log_ssdlc_event(event: SSDLCEvent, subject: str, msg: str = "") -> None:
    """Log a security event in SSDLC-compliant structured format.

    Args:
        event: The SSDLC event type.
        subject: Context for the event — a service name, username, etc.
        msg: Optional additional message appended to the description.
    """
    level = _EVENT_LEVELS[event]
    description_template = _EVENT_DESCRIPTIONS[event]
    description = f"{description_template % subject} {msg}".strip()

    now = datetime.now(timezone.utc).astimezone()

    logger.warning(
        {
            "datetime": now.isoformat(),
            "appid": f"{APPID_PREFIX}.{subject.split(',')[0]}",
            "event": f"{event.value}:{subject}",
            "level": level,
            "description": description,
        }
    )
