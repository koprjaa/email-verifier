"""Tests for the decisions the verifier makes without touching the network."""

import sys

import pytest

classify = sys.modules["verifier.classify"]

REPUTATION_SENSITIVE_DOMAINS = classify.REPUTATION_SENSITIVE_DOMAINS
TEMPORARY_ERROR_CODES = classify.TEMPORARY_ERROR_CODES
choose_sender = classify.choose_sender
is_blocked_ip = classify.is_blocked_ip
is_disposable_domain = classify.is_disposable_domain
is_reputation_error = classify.is_reputation_error
is_temporary_error = classify.is_temporary_error

DISPOSABLE = {"mailinator.com", "10minutemail.com", "guerrillamail.com"}


# --- is_blocked_ip ----------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",        # loopback
        "::1",              # loopback, v6
        "10.0.0.1",         # private
        "172.16.0.1",       # private
        "192.168.1.1",      # private
        "169.254.169.254",  # link-local, the cloud metadata address
        "fe80::1",          # link-local, v6
        "224.0.0.1",        # multicast
        "0.0.0.0",          # unspecified
        "100.64.0.1",       # carrier-grade NAT
        "100.127.255.254",  # carrier-grade NAT, upper end
    ],
)
def test_an_address_that_is_not_publicly_routable_is_refused(ip):
    """An MX record is attacker-controlled, so following one must not reach inside."""
    assert is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"])
def test_a_public_address_is_allowed(ip):
    assert is_blocked_ip(ip) is False


@pytest.mark.parametrize("ip", ["", "not an ip", "999.999.999.999", "10.0.0", None])
def test_an_address_that_will_not_parse_is_refused(ip):
    """Unparseable means unknown, and unknown is not safe."""
    assert is_blocked_ip(ip) is True


def test_the_edges_of_the_cgnat_range():
    """is_private does not cover 100.64.0.0/10, so it is checked separately."""
    assert is_blocked_ip("100.63.255.255") is False
    assert is_blocked_ip("100.64.0.0") is True
    assert is_blocked_ip("100.127.255.255") is True
    assert is_blocked_ip("100.128.0.0") is False


# --- is_disposable_domain ---------------------------------------------------


def test_a_listed_domain_is_disposable():
    assert is_disposable_domain("mailinator.com", DISPOSABLE) is True


def test_the_check_ignores_case():
    assert is_disposable_domain("MailInator.COM", DISPOSABLE) is True


def test_a_subdomain_of_a_listed_domain_is_disposable():
    """One entry has to cover every host a throwaway service hands out."""
    assert is_disposable_domain("mail.mailinator.com", DISPOSABLE) is True


def test_a_domain_that_merely_ends_in_a_listed_name_is_not_matched():
    assert is_disposable_domain("notmailinator.com", DISPOSABLE) is False


@pytest.mark.parametrize("domain", ["gmail.com", "seznam.cz", "example.co.uk"])
def test_an_ordinary_domain_is_not_disposable(domain):
    assert is_disposable_domain(domain, DISPOSABLE) is False


def test_an_empty_blocklist_matches_nothing():
    assert is_disposable_domain("mailinator.com", set()) is False


# --- is_temporary_error -----------------------------------------------------


@pytest.mark.parametrize("code", sorted(TEMPORARY_ERROR_CODES))
def test_every_listed_code_reads_as_temporary(code):
    assert is_temporary_error(code, "") is True


@pytest.mark.parametrize("code", [250, 500, 501, 550, 551])
def test_a_permanent_refusal_is_not_temporary(code):
    assert is_temporary_error(code, "") is False


def test_the_permanent_looking_codes_are_temporary_on_purpose():
    """552, 553 and 554 are permanent by the standard.

    In practice a server sends them when it dislikes the sender or the
    connection rather than the recipient, so treating them as "no such mailbox"
    would report a live address as invalid.
    """
    for code in (552, 553, 554):
        assert is_temporary_error(code, "") is True


@pytest.mark.parametrize(
    "message",
    [
        "Try again later",
        "Service temporary failure",
        "Server busy",
        "Rate limit exceeded",
        "Mailbox quota exceeded",
        "System overloaded",
        "Connection throttled",
    ],
)
def test_a_busy_message_reads_as_temporary_whatever_the_code(message):
    assert is_temporary_error(550, message) is True


def test_the_message_match_is_a_substring_not_a_word():
    """"temporarily" does not contain the pattern "temporary", so it is missed.

    A server that writes "temporarily unavailable" is refused as permanent.
    Widening the pattern is a judgement call about false positives, so the
    behavior is recorded here rather than changed.
    """
    assert is_temporary_error(550, "Service temporarily unavailable") is False
    assert is_temporary_error(450, "Service temporarily unavailable") is True


def test_the_message_match_ignores_case():
    assert is_temporary_error(550, "TRY AGAIN LATER") is True


@pytest.mark.parametrize("message", ["", None, "User unknown", "No such user here"])
def test_a_plain_rejection_is_not_temporary(message):
    assert is_temporary_error(550, message) is False


# --- is_reputation_error ----------------------------------------------------


def test_a_554_is_about_the_sender():
    assert is_reputation_error(554, "") is True


@pytest.mark.parametrize(
    "message",
    [
        "Your IP has poor reputation",
        "Sender reputation is low",
        "Message rejected as spam",
        "Your address is blocked",
        "Host is blacklisted",
        "Message rejected",
    ],
)
def test_a_sender_complaint_is_recognized(message):
    assert is_reputation_error(550, message) is True


@pytest.mark.parametrize("message", ["", None, "User unknown", "Mailbox full"])
def test_a_recipient_problem_is_not_a_reputation_error(message):
    assert is_reputation_error(550, message) is False


# --- choose_sender ----------------------------------------------------------


SENDERS = {"seznam.cz": "probe@seznam.cz", "gmail.com": "probe@gmail.com"}
DEFAULT = "default@example.com"


def test_an_override_wins_over_everything():
    assert choose_sender("seznam.cz", SENDERS, DEFAULT, "forced@x.cz") == "forced@x.cz"


def test_a_sensitive_domain_gets_a_sender_at_the_same_provider():
    """Seznam answers a probe from its own users and tarpits everyone else."""
    assert choose_sender("seznam.cz", SENDERS, DEFAULT) == "probe@seznam.cz"


def test_a_sensitive_domain_without_a_matching_sender_falls_back_to_a_trusted_one():
    assert choose_sender("post.cz", SENDERS, DEFAULT) == "probe@gmail.com"


def test_a_sensitive_domain_with_no_usable_sender_falls_back_to_the_default():
    assert choose_sender("post.cz", {}, DEFAULT) == DEFAULT


def test_an_ordinary_domain_uses_its_own_sender_when_there_is_one():
    assert choose_sender("gmail.com", SENDERS, DEFAULT) == "probe@gmail.com"


def test_an_ordinary_domain_otherwise_uses_the_default():
    assert choose_sender("example.com", SENDERS, DEFAULT) == DEFAULT


def test_the_domain_lookup_ignores_case():
    assert choose_sender("SEZNAM.CZ", SENDERS, DEFAULT) == "probe@seznam.cz"


@pytest.mark.parametrize("domain", sorted(REPUTATION_SENSITIVE_DOMAINS))
def test_every_sensitive_domain_is_handled(domain):
    assert choose_sender(domain, SENDERS, DEFAULT) == "probe@gmail.com" or domain == "seznam.cz"
