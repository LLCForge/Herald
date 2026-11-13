# Security Policy

Herald runs close to network infrastructure, so we take security reports seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| `main` branch | Yes (best effort) |
| Older releases | No, please upgrade |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for security problems.**

Report privately through GitHub Security Advisories:

1. Go to [https://github.com/LLCForge/Herald/security/advisories/new](https://github.com/LLCForge/Herald/security/advisories/new).
2. Describe the issue, affected version or commit, and steps to reproduce.
3. Include a proof of concept if you have one. Strip any real customer data, IP addresses or credentials from captures and logs.

What to expect:

- Acknowledgement within **3 business days**.
- An initial assessment and severity rating within **10 business days**.
- A fix or mitigation plan, coordinated disclosure date, and credit in the advisory (unless you prefer to stay anonymous).

## In scope

- Injection into alert messages (Telegram HTML, Slack/Discord/Teams markup, webhook JSON, e-mail, syslog) via crafted certificate fields.
- Missed alerts caused by parser errors on valid certificates or tiles (silent detection gaps).
- Bypasses of tree head verification: forged checkpoints or STHs, consistency proofs or tiles that Herald accepts although they do not match the signed root.
- The management listener: unauthenticated access to `/v1/silences` or `POST /v1/reload`, request smuggling, or resource exhaustion through `/metrics`, `/healthz`, `/readyz`.
- Telegram action buttons: presses accepted from a user or chat that is not configured, forged callback data, or actions with a larger effect than documented (verdict, one bounded silence, one alert).
- DNS (CAA) answer parsing, CRL parsing and crt.sh parsing: crashes, unbounded memory or CPU use.
- Leakage of any secret (bot tokens, webhook HMAC secrets, SMTP passwords, routing keys, admin tokens) in logs, errors or alerts.
- Dependency vulnerabilities that are reachable from Herald's code paths.

## Out of scope

- Vulnerabilities in third-party services or protocols themselves (report those upstream).
- Issues that require an attacker to already control the host or the config file.
- Denial of service by volumetric flooding of the network the tool runs on.

## Hardening recommendations

- Run as an unprivileged user; Herald needs no capabilities (the systemd unit uses `DynamicUser=yes` and an empty capability set).
- Bind the management listener (`[metrics] listen`) to localhost or a management network. Mount `/v1/silences` and `/v1/reload` only with a strong `*_env` admin token.
- Use a dedicated bot for `[telegram_actions]`, a private chat or group, and list only the people who should triage certificates in `allowed_user_ids`.
- Prefer DNS-over-HTTPS or a resolver you trust for CAA lookups: a spoofed answer can mute or raise CAA alerts.
- Set `hmac_secret_env` on webhook sinks and verify signatures on the receiving side.
- Keep secrets in environment variables or your secret manager, never in the config file or in version control.
