#
# Project: email-verifier
# File:    classify.py
#
# Description:
# The decisions the verifier makes from an address, an IP, or an SMTP reply, without touching the network.
#
# Author:
# Jan Alexandr Kopřiva
# jan.alexandr.kopriva@gmail.com
#
# License: MIT
#

"""These are the judgement calls the verifier makes without asking anything of the
network: whether an address may be probed at all, and what a server's answer
means. They sit here so they can be read and tested on their own.
"""

import ipaddress

# SMTP codes the verifier treats as "ask again later" rather than a verdict.
#
# 421 and the 45x codes are temporary by the standard. 552, 553 and 554 are
# permanent, and are listed here on purpose: in practice a server sends them
# when it dislikes the sender or the connection rather than the recipient, so
# treating them as a "no such mailbox" would report a live address as invalid.
TEMPORARY_ERROR_CODES = {421, 450, 451, 452, 454, 458, 459, 471, 472, 552, 553, 554}

# Words a server uses when it is busy rather than refusing the recipient.
TEMPORARY_ERROR_PATTERNS = (
    "temporary",
    "try again",
    "later",
    "busy",
    "overloaded",
    "rate limit",
    "throttled",
    "quota",
    "limit exceeded",
)

# Words a server uses when it dislikes the sender, not the recipient. A refusal
# on those grounds says nothing about whether the mailbox exists.
REPUTATION_ERROR_PATTERNS = (
    "poor reputation",
    "reputation",
    "spam",
    "blocked",
    "blacklisted",
    "rejected",
)

# Czech providers that tarpit an unknown sender rather than answer honestly.
REPUTATION_SENSITIVE_DOMAINS = frozenset(
    {"centrum.cz", "post.cz", "seznam.cz", "email.cz"}
)

# Senders these providers are most likely to accept a probe from.
TRUSTED_SENDER_DOMAINS = ("gmail.com", "outlook.com", "yahoo.com")

# Carrier-grade NAT, RFC 6598. is_private does not cover it.
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def is_blocked_ip(ip_str: str) -> bool:
    """True when the address must not be connected to.

    An MX record is controlled by whoever owns the domain, so following one
    blindly lets a stranger point this tool at a private network. Anything that
    is not globally routable is refused, and an address that will not parse is
    refused too rather than assumed safe.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    if ip.version == 4 and ip in CGNAT_NETWORK:
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_disposable_domain(domain: str, disposable_domains) -> bool:
    """True when the domain, or the domain it sits under, is throwaway.

    A subdomain is checked against its parent, so one entry covers every host a
    disposable service hands out.
    """
    normalized = domain.lower()
    if normalized in disposable_domains:
        return True
    parts = normalized.split(".")
    return len(parts) > 2 and ".".join(parts[-2:]) in disposable_domains


def is_temporary_error(code: int, message: str) -> bool:
    """True when an SMTP refusal means try again rather than no such mailbox."""
    if code in TEMPORARY_ERROR_CODES:
        return True
    lowered = (message or "").lower()
    return any(pattern in lowered for pattern in TEMPORARY_ERROR_PATTERNS)


def is_reputation_error(code: int, message: str) -> bool:
    """True when a refusal is about the sender rather than the recipient.

    554 is the code a server uses to reject a whole transaction, which in
    practice means it did not like where the probe came from.
    """
    if code == 554:
        return True
    lowered = (message or "").lower()
    return any(pattern in lowered for pattern in REPUTATION_ERROR_PATTERNS)


def choose_sender(
    recipient_domain: str,
    senders_by_domain: dict,
    default_sender: str,
    override: str | None = None,
) -> str:
    """Address to probe from.

    A provider that watches its senders is more likely to answer a probe from
    one of its own users, so a matching sender is preferred, then one at a
    provider that is widely trusted.
    """
    if override:
        return override

    domain = recipient_domain.lower()
    if domain in REPUTATION_SENSITIVE_DOMAINS:
        if domain in senders_by_domain:
            return senders_by_domain[domain]
        for trusted in TRUSTED_SENDER_DOMAINS:
            if trusted in senders_by_domain:
                return senders_by_domain[trusted]

    return senders_by_domain.get(domain, default_sender)
