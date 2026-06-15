# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

1. Go to the **Security** tab on this repository
2. Click **"Report a vulnerability"**
3. Fill in the details

Or contact via GitHub profile: https://github.com/rithinkrishnakv

Response within **72 hours**. We coordinate a fix before public disclosure.

## Scope

In scope:
- Policy bypass — unauthorized process not detected
- Kill logic flaws — process surviving termination
- Privilege escalation via AegisMimic itself
- Audit log tampering
- Canary token predictability

Out of scope:
- Windows compatibility — Linux-only by design
- Root requirement — expected and documented
- Transient accessor race — known limitation, documented

## Responsible Use

AegisMimic is a defensive tool intended to protect systems you own
or have explicit authorization to protect.