# Security Policy

## Reporting a vulnerability

Do not publish credentials or exploit details in a public issue. Open a private GitHub security advisory for the repository. Remove server addresses, usernames, passwords, private keys, API keys, cookies, device codes, tokens, and authentication files from all attachments.

## Security boundaries

- Verify the displayed SSH host fingerprint through the server provider's console before accepting it.
- Download release files only from this repository and verify the published SHA-256 value.
- The generated private key remains on the Windows computer; only its public key is installed remotely.
- Treat remote `~/.codex/auth.json` as a password if file credential storage is enabled.
- Review changes before running the tool against production infrastructure.
