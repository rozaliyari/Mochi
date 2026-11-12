# Security model and limitations

The UI runs as the current user; a foreground root helper controls OpenVPN and routes. Its Unix control socket is owner-only. Processes running as that same user can use the socket. The source directory and interpreter must be trusted before sudo execution. This is not a signed privileged service or Network Extension.

## Password storage

Optional fixed-password and encrypted-private-key passwords use macOS generic-password Keychain items through Security.framework. Secret data is not passed to a shell, command-line arguments, JSON preferences or a password file. Each profile has an opaque credential identifier and a binding to the actual sanitized VPN configuration. A changed profile/remote server does not automatically receive the old saved password. Usernames remain ordinary private preferences.

Saved two-step logins are reused without showing the username/key dialog when the profile binding still matches; a fresh 2FA code remains a separate prompt. The visible Save checkbox controls writes/updates; Forget deletes the saved local item. Profiles and credentials are separate: removing a profile alone does not delete its Keychain item. Current phone-code responses never enter the saved-item payload. An optional Authenticator TOTP setup seed is included only when the user enables the setup-key option and selects Save login in Mac Keychain. Otherwise it stays in session memory. The seed is distinct from the VPN encrypted-key password. QR scanning is deferred in 0.17; manual setup-key entry remains available. Python/Tcl/ctypes do not guarantee memory zeroization. Keychain ACLs are associated with the Python runtime; a signed packaged app with a dedicated identity would provide a stronger boundary. macOS may request access confirmation or require the login Keychain to be unlocked.

The project follows Apple's [generic password item](https://developer.apple.com/documentation/security/ksecclassgenericpassword) and [Keychain item management](https://developer.apple.com/documentation/security/using-the-keychain-to-manage-user-secrets) APIs. No broad Keychain enumeration is used; only this app's exact service/account pair is queried or deleted.

## Profiles and routes

- The importer accepts a small transport/TLS allowlist and inline CA/certificate/key/tls-auth/tls-crypt blocks. Scripts, plugins, config includes, arbitrary file references and management overrides are rejected.
- TLS CA/server verification stays enabled. Null encryption is rejected. Provider-declared non-AEAD ciphers require an actual MAC; `auth none` is accepted only for AEAD encryption without tls-auth.
- `route-nopull`, `route-noexec`, `script-security 1`, and filters prevent imported/server default-route requests from taking over the system default. Imported route suggestions require review. IPv4 only.
- Destinations overlapping another VPN, another VPN's DNS, or incompatible DIRECT routes fail. Broad OpenVPN CIDRs are split to exclude transport endpoint hosts; explicitly routing a transport host still fails. DNS-learned endpoint routes are also rejected. More-specific existing routes and interface-assigned tunnel networks still require device-level review. Conflicting assigned tunnel subnets are unsupported.
- Domain rules install IP routes. A shared CDN IP cannot safely be separated by HTTP hostname. Browser DoH, existing connections, cached answers and literal IPv6 can bypass this mechanism. Exact-host warming and same-session remembered routes reduce cache issues but do not provide full traffic interception.

## DNS and cleanup

A loopback UDP/TCP forwarder commits routes before returning validated A answers. It handles CNAME answer chains, rejects mismatched questions/IDs and does not route unrelated additional records. Selected resolver requests suppress AAAA and HTTPS/SVCB address hints. Query/response sizes, timeouts and concurrency are bounded. Existing `/etc/resolver` files/symlinks are never overwritten. Ownership checks preserve user edits; a root-owned journal supports recovery of unchanged stale DNS files on the next supervisor start.

Normal exit/SIGTERM stop child tunnels and remove recorded routes/files. SIGKILL, power loss, helper failure or manual routing edits can leave child processes/routes; automatic crash recovery is incomplete. Startup refuses a second supervisor or detected orphan OpenVPN children. Review exact processes/session directories and routing entries after a crash; do not flush another VPN's routes.

**There is no kill switch, PF enforcement, automatic reconnect or guarantee against leaks.** In the installed 0.11 app, closing the dashboard hides it and keeps connections running; Quit from the menu-bar icon disconnects all its tunnels. Direct source execution retains the close-and-disconnect behavior. DIRECT means the system gateway before the helper started, which may already be affected by other VPN software.

## Publishing and reporting

Real VPN exports, certificates/private keys, passwords, phone codes, local preferences and private logs do not belong in Git or issue attachments. `.gitignore` and the source-tree check cover common file leaks; they cannot guarantee detection of every secret or remove existing Git history. Report failures with redacted option names and reproducible dummy fixtures. No production-readiness or ten-real-tunnel reliability claim is made by local tests.
