"""Unit tests for SSDLC security event logging."""

import datetime
import unittest
from unittest import mock

from ssdlc import SSDLCEvent, log_ssdlc_event


class TestSSDLCLogging(unittest.TestCase):
    """Test SSDLC security event logging."""

    @mock.patch("ssdlc.logger")
    @mock.patch("ssdlc.datetime")
    def test_log_sys_restart(self, mock_datetime, mock_logger):
        """Test SYS_RESTART event is logged correctly."""
        mock_now = mock.MagicMock()
        mock_now.isoformat.return_value = "2025-01-01T12:00:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        log_ssdlc_event(SSDLCEvent.SYS_RESTART, "ssh")

        logged = mock_logger.warning.call_args[0][0]
        assert logged["event"] == "sys_restart:ssh"
        assert logged["level"] == "WARN"
        assert logged["appid"] == "charm.userdir-ldap.ssh"
        assert logged["description"] == "Service ssh restarted"
        assert logged["datetime"] == "2025-01-01T12:00:00+00:00"

    @mock.patch("ssdlc.logger")
    @mock.patch("ssdlc.datetime")
    def test_log_user_created(self, mock_datetime, mock_logger):
        """Test USER_CREATED event is logged correctly."""
        mock_now = mock.MagicMock()
        mock_now.isoformat.return_value = "2025-01-01T12:00:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        log_ssdlc_event(SSDLCEvent.USER_CREATED, "sshdist", "Additional info")

        logged = mock_logger.warning.call_args[0][0]
        assert logged["event"] == "user_created:sshdist"
        assert logged["level"] == "WARN"
        assert logged["appid"] == "charm.userdir-ldap.sshdist"
        assert logged["description"] == "User created: sshdist Additional info"
        assert logged["datetime"] == "2025-01-01T12:00:00+00:00"

    @mock.patch("ssdlc.logger")
    @mock.patch("ssdlc.datetime")
    def test_log_ssdlc_system_event_datetime_format(self, mock_datetime, mock_logger):
        """Test that datetime is in ISO 8601 format with timezone."""
        # Use a real datetime to test formatting
        test_time = datetime.datetime(2025, 1, 15, 14, 30, 45, tzinfo=datetime.timezone.utc)
        mock_datetime.now.return_value.astimezone.return_value = test_time

        log_ssdlc_event(SSDLCEvent.SYS_RESTART, "ssh")

        logged_data = mock_logger.warning.call_args[0][0]
        # Verify ISO 8601 format with timezone
        assert logged_data["datetime"] == "2025-01-15T14:30:45+00:00"

    @mock.patch("ssdlc.logger")
    @mock.patch("ssdlc.datetime")
    def test_log_user_updated(self, mock_datetime, mock_logger):
        """Test USER_UPDATED event is logged correctly."""
        mock_now = mock.MagicMock()
        mock_now.isoformat.return_value = "2025-01-01T12:00:00+00:00"
        mock_datetime.now.return_value.astimezone.return_value = mock_now

        log_ssdlc_event(SSDLCEvent.USER_UPDATED, "admins,devops", "sudoers updated")

        logged = mock_logger.warning.call_args[0][0]
        assert logged["event"] == "user_updated:admins,devops"
        assert logged["level"] == "WARN"
        assert logged["appid"] == "charm.userdir-ldap.admins"
        assert logged["description"] == "User updated: admins,devops sudoers updated"
        assert logged["datetime"] == "2025-01-01T12:00:00+00:00"
