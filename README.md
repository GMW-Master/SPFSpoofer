# SPFSpoofer
This repository contains a single-process SMTP demo server intended for security testing, training, and deliverability demonstrations. It runs:

- An acceptor on 0.0.0.0 ports 25 and 2525 (plain SMTP, no AUTH/TLS)
- A local relay on 127.0.0.1:2526 (plain SMTP, no AUTH/TLS)
- DKIM handling in the acceptor:
  - Attempts real DKIM signing using a private key (if provided)
  - Falls back to inserting a dummy DKIM-Signature header when the real key is unavailable or fails
- Final delivery from the relay is direct-to-MX on port 25 (opportunistic STARTTLS to recipient if offered)

Ideal for:
- Demonstrating how SPF/DKIM/DMARC validation occurs at the receiver
- Testing brand/domain spoofing scenarios in a controlled environment
- Lab exercises requiring an SMTP acceptor and internal relay without TLS/AUTH friction

Important: This is a lab/demo tool. Do not expose it to the Internet in production environments.

## File

- smtp_demo.py (use the script you pasted in your last message; instructions below reference its configurable values)

## Configure Values To Change

Edit the “Config” section at the top of the script to set attacker/victim identities, paths, and behavior.

- HELLO_NAME
  - What the server uses in its EHLO/HELO greeting.
  - Example: "mail.attacker.example" or the lab hostname.
  - In the provided script, placeholder:
    - "<Attacker's Domain>"

- Listener bind and ports
  - ACCEPTOR_HOST, ACCEPTOR_PORT_25, ACCEPTOR_PORT_2525
    - Default: 0.0.0.0 on ports 25 and 2525
    - If running without root, change ACCEPTOR_PORT_25 to a high port (e.g., 2527).
  - RELAY_HOST, RELAY_PORT
    - Default: 127.0.0.1:2526 (local relay in the same process)

- SAVE_DIR
  - Local path where the script will save raw and “signed” messages.
  - Example: "/tmp/smtp_demo" or any writable directory.
  - In the provided script, placeholder:
    - "<log stroage path>"

- DKIM configuration (for real signing; otherwise dummy DKIM is added)
  - DKIM_PRIVKEY_PATH
    - Path to the DKIM private key (PEM). If the file is missing or unreadable, the script will automatically add a dummy DKIM header instead of real signing.
    - Placeholder: "<DKIM private key path>"
  - DKIM_SELECTOR
    - Example: b"google" (keep as bytes)
  - DKIM_DOMAIN
    - Domain to sign as (the “d=” value).
    - Placeholder: b"<Victim Dmain>"
    - Set to something like b"victim.example"
  - HEADERS_TO_SIGN
    - Headers to include in the signature. Defaults are fine for most demos.

- normalize_headers() domain for Message-ID
  - The domain used to create a Message-ID if missing:
    - make_msgid(domain="<attacker's Domain>")
  - Replace "<attacker's Domain>" with the domain you want displayed in Message-ID (e.g., attacker.example).

Summary of placeholders to replace:
- "<Attacker's Domain>" in HELLO_NAME and in normalize_headers()
- "<Victim Dmain>" in DKIM_DOMAIN
- "<DKIM private key path>" in DKIM_PRIVKEY_PATH
- "<log stroage path>" in SAVE_DIR

Example configuration:
- HELLO_NAME = "mail.attacker.example"
- SAVE_DIR = "/tmp/smtp_demo"
- DKIM_PRIVKEY_PATH = "/home/lab/dkim/private.key"
- DKIM_SELECTOR = b"demo"
- DKIM_DOMAIN = b"victim.example"

## How It Works (Flow)

1. A client connects to the acceptor on 0.0.0.0:25 or :2525 and performs SMTP (EHLO/HELO, MAIL FROM, RCPT TO, DATA).
2. On DATA:
   - The message is normalized (ensures Date and Message-ID).
   - The script attempts real DKIM signing using DKIM_PRIVKEY_PATH and DKIM_DOMAIN.
   - If real signing fails for any reason, it injects a dummy DKIM-Signature header instead.
   - The modified message is saved to SAVE_DIR and forwarded to the local relay at 127.0.0.1:2526.
3. The local relay resolves MX records for each recipient domain and attempts direct SMTP delivery on port 25 (STARTTLS if offered).

## Dependencies

Install Python 3.9+ and the following libraries:

- aiosmtpd
- dkimpy
- dnspython

On most systems:

- pip install aiosmtpd dkimpy dnspython

If using system Python on Linux/macOS, you may need sudo:

- sudo python3 -m pip install aiosmtpd dkimpy dnspython

## Running

A) Quick start (non-privileged ports)

- Edit the script to change:
  - ACCEPTOR_PORT_25 = 2527
  - ACCEPTOR_PORT_2525 = 2528
- Start the server:
  - python3 smtp_demo.py
- Test locally:
  - telnet 127.0.0.1 2527
  - EHLO test
  - MAIL FROM:<sender@attacker.example>
  - RCPT TO:<victim@gmail.com>
  - DATA
  - Paste headers/body, end with a single dot on a line by itself
  - QUIT

B) Binding to port 25 (requires root/admin privileges)

- Ensure no other MTA (postfix, sendmail) is listening on port 25.
- Start:
  - sudo python3 smtp_demo.py

C) Check local relay port

- Verify the embedded relay is listening:
  - telnet 127.0.0.1 2526
  - Quit with Ctrl+] then “quit”

## Execution Notes and Troubleshooting

- Permission denied binding to port 25
  - Run as root (sudo) or change to a high port (e.g., 2527).

- Port already in use
  - Stop the other SMTP service or change ports in the script.

- No delivered mail / “Network is unreachable” when sending to MX
  - The host likely cannot egress on TCP/25 (common in cloud environments).
  - This script performs direct-to-MX delivery from the local relay; if outbound 25 is blocked, deliveries will fail.
  - Options:
    - Request unblocking of outbound 25 from the provider.
    - Modify the relay section to send to a reachable smarthost on a different port instead of MX.

- DKIM header missing in received email
  - If real signing fails and dummy injection is disabled or mis-edited, the header may be absent.
  - In this script path, DKIM is attempted; if it fails, a dummy DKIM header is added automatically.
  - Check SAVE_DIR for msg_*_signed.eml and verify the DKIM-Signature header appears there.

## Where to Customize Attacker/Victim Values

- HELLO_NAME
  - Set to attacker’s domain or host for SMTP greeting appearance.

- normalize_headers() Message-ID domain
  - Replace "<attacker's Domain>" to control the domain shown in generated Message-ID.

- DKIM_DOMAIN
  - Replace "<Victim Dmain>" with the domain to appear in the DKIM “d=” tag.
  - If the private key is valid and the DNS has the selector TXT published, receivers can validate DKIM.
  - If not, the script falls back to dummy DKIM.

- DKIM_PRIVKEY_PATH
  - Set to a valid key file path if real signing is desired.
  - If missing, dummy DKIM will be used.

- SAVE_DIR
  - Set to any writable location for saving raw/signed copies for inspection.

## Safe Telnet Test Flow

- EHLO test
- MAIL FROM:<sectest@attacker.example>
- RCPT TO:<recipient@targetdomain.tld>
- DATA
- Then paste headers and body:
  - From: "Display Name" <sectest@attacker.example>
  - To: recipient@targetdomain.tld
  - Subject: Lab Test
  - (blank line)
  - Body line 1
  - Body line 2
- End with a single dot on a line by itself
- QUIT

Important: Do not paste headers before issuing the DATA command.

## Legal and Ethical Use

This tool is meant for controlled demonstrations, internal testing, and educational purposes by authorized personnel. Do not use it to send unsolicited messages or to impersonate domains without explicit permission.

## Quick Checklist

- Replace placeholders:
  - HELLO_NAME ("<Attacker's Domain>")
  - DKIM_DOMAIN (b"<Victim Dmain>")
  - DKIM_PRIVKEY_PATH ("<DKIM private key path>")
  - SAVE_DIR ("<log stroage path>")
  - Message-ID domain inside normalize_headers()

- Install dependencies:
  - pip install aiosmtpd dkimpy dnspython

- Run on high ports without sudo, or use sudo for port 25.

- Verify local relay (127.0.0.1:2526) is started before sending.

- If outbound 25 is blocked, modify relay delivery to use a reachable smarthost (optional enhancement).
