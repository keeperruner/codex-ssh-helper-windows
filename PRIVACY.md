# Privacy

Codex SSH Helper runs locally and does not contain telemetry or an analytics service.

It sends SSH authentication data to the server selected by the user. Optional installation and authorization contact official upstream services. "No telemetry" does not mean that setup performs no network communication or saves no connection configuration.

The following values are processed only to perform the requested setup:

- SSH server address and port
- SSH username and one-time password
- generated public/private SSH key pair
- SSH server host key and fingerprint
- Codex device-authentication URL and one-time code

The program does not intentionally persist the SSH password. It writes the generated SSH key pair, a per-host `known_hosts` file, and a managed block in the current Windows user's SSH configuration. It may write Codex configuration and authentication data on the remote host when the user explicitly enables the relevant options.

Do not include passwords, private keys, API keys, device codes, `auth.json`, cookies, real server addresses, or unredacted logs in public bug reports.

The local progress page displays the target address, username, key path and device code when applicable. Redact those values before sharing screenshots. Public repository assets use only an empty initial screen and documentation examples. See [RELEASE_CHECK.md](RELEASE_CHECK.md) for the scope of the release-file review.
