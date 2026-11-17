from __future__ import annotations

import sys
import threading
from unittest.mock import Mock

from homeassistant.const import CONF_PASSWORD
import pytest

from custom_components.jablotron100.const import (
	AUTHORISATION_LOGIN_MIN_INTERVAL,
	AUTHORISATION_PING_INTERVAL,
	AUTHORISATION_PING_REPLY_TIMEOUT,
	DEVICE_STATE_PACKETS_REFRESH_INTERVAL,
	UI_CONTROL_AUTHORISATION_END,
	UI_CONTROL_AUTHORISATION_PING,
)
from custom_components.jablotron100.jablotron import Jablotron

PING = Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_PING)
ENABLE_DEVICE_STATES = Jablotron.create_packet_enable_device_states()


class Clock:
	def __init__(self) -> None:
		self.now = 1000.0

	def __call__(self) -> float:
		return self.now


@pytest.fixture
def session(monkeypatch):
	clock = Clock()
	monkeypatch.setattr(sys.modules[Jablotron.__module__].time, "monotonic", clock)

	jablotron = object.__new__(Jablotron)
	jablotron._config = {CONF_PASSWORD: "1234"}
	jablotron._authorisation_lock = threading.Lock()
	jablotron._login_failed = threading.Event()
	jablotron._authorisation_restore_pending = False
	jablotron._init_authorisation_session()
	jablotron._stream_stop_event = Mock()
	jablotron._stream_stop_event.is_set.return_value = False

	packets = []
	jablotron._send_packet = Mock(side_effect=packets.append)
	jablotron._send_packets = Mock(side_effect=packets.extend)
	return jablotron, packets, clock


def test_ping_packet_matches_protocol():
	assert PING == b"\x80\x01\x02"


def test_first_keepalive_logs_in(session):
	jablotron, packets, clock = session
	assert jablotron._is_login_needed()
	assert jablotron._send_keepalive()
	assert packets == Jablotron.create_packets_keepalive("1234")
	assert jablotron._authorisation_open.is_set()
	assert not jablotron._is_login_needed()


def test_open_channel_is_kept_with_pings_not_logins(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	packets.clear()

	# One hour of keepalive cycles every 0.5 s while the central unit answers every ping.
	for _ in range(7200):
		clock.now += 0.5
		assert not jablotron._is_login_needed()
		if jablotron._send_authorisation_ping_if_due() and packets and packets[-1] in (PING, ENABLE_DEVICE_STATES):
			jablotron._authorisation_ping_replied()

	assert Jablotron.create_packet_authorisation_code("1234") not in packets
	assert packets.count(PING) == 3600 // AUTHORISATION_PING_INTERVAL
	assert packets.count(ENABLE_DEVICE_STATES) == 3600 // DEVICE_STATE_PACKETS_REFRESH_INTERVAL


def test_ping_is_not_sent_before_interval(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	packets.clear()
	clock.now += AUTHORISATION_PING_INTERVAL - 0.5
	assert not jablotron._send_authorisation_ping_if_due()
	assert packets == []
	clock.now += 0.5
	assert jablotron._send_authorisation_ping_if_due()
	assert packets == [PING]


def test_no_ping_without_open_channel(session):
	jablotron, packets, clock = session
	clock.now += 60
	assert not jablotron._send_authorisation_ping_if_due()
	assert packets == []


def test_ping_skipped_while_transaction_holds_lock(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	packets.clear()
	clock.now += AUTHORISATION_PING_INTERVAL
	with jablotron._authorisation_lock:
		assert not jablotron._send_authorisation_ping_if_due()
	assert packets == []
	assert jablotron._send_authorisation_ping_if_due()
	assert packets == [PING]


def test_channel_closed_by_central_unit_logs_in_again_after_min_interval(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	jablotron._authorisation_open.clear()  # UI_CONTROL_AUTHORISATION_END received
	clock.now += AUTHORISATION_LOGIN_MIN_INTERVAL - 1
	assert not jablotron._is_login_needed()
	clock.now += 1
	assert jablotron._is_login_needed()


def test_missing_ping_reply_logs_in_again_once_replies_were_seen(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	for _ in range(AUTHORISATION_LOGIN_MIN_INTERVAL // AUTHORISATION_PING_INTERVAL + 1):
		clock.now += AUTHORISATION_PING_INTERVAL
		jablotron._authorisation_ping_replied()
		assert not jablotron._is_login_needed()
	clock.now += AUTHORISATION_PING_REPLY_TIMEOUT
	assert not jablotron._is_login_needed()
	clock.now += 1
	assert jablotron._is_login_needed()
	assert not jablotron._authorisation_open.is_set()


def test_unanswered_pings_do_not_force_logins_when_central_unit_never_replies(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	clock.now += 3600
	assert not jablotron._is_login_needed()


def test_failed_login_is_retried_at_most_every_min_interval(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	jablotron._authorisation_open.clear()  # login error packet received
	logins = 1
	for _ in range(7200):
		clock.now += 0.5
		if jablotron._is_login_needed():
			jablotron._send_keepalive()
			jablotron._authorisation_open.clear()
			logins += 1
	assert logins <= 3600 // AUTHORISATION_LOGIN_MIN_INTERVAL + 1


def test_restore_pending_forces_login(session):
	jablotron, packets, clock = session
	jablotron._send_keepalive()
	jablotron._authorisation_restore_pending = True
	clock.now += AUTHORISATION_LOGIN_MIN_INTERVAL
	assert jablotron._is_login_needed()
	packets.clear()
	assert jablotron._send_keepalive()
	assert packets[0] == Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END)


@pytest.mark.parametrize(
	("packet", "ping", "end"),
	[
		(b"\x80\x01\x02", True, False),
		(b"\x80\x01\x01", False, True),
		(b"\x80\x02\x1b\x03", False, False),
		(b"\x52\x01\x02", False, False),
	],
)
def test_incoming_authorisation_packets(packet, ping, end):
	assert Jablotron._is_authorisation_ping_packet(packet) is ping
	assert Jablotron._is_authorisation_end_packet(packet) is end
