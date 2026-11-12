---
name: mochi-development
description: Develop, debug and package the Mochi macOS VPN application in this repository, including OpenVPN authentication, destination routing, native menu controls and grouped VLESS/VMess imports.
---

# Mochi development

Resolve the repository root from this skill's directory. Read `docs/AI_HANDOFF.md` for current state and `docs/PROJECT_GUIDE.md` for the relevant source map. Read `docs/SECURITY.md` before authentication, helper, DNS or routing changes; read `docs/PORTABLE-BUILD.md` for packaging and redistribution sources.

Keep the UI English, concise, system-themed and paste-enabled. Configure saved credentials when importing/editing a profile. Reuse saved fixed passwords; request a fresh phone code only for the appropriate server challenge. Distinguish login password, encrypted private-key password and TOTP setup seed. Inspect the current redacted failure stage before diagnosing auth errors; never print raw credentials, subscription URLs or management responses.

Mochi has a foreground root helper, not a permanently installed authorized service. Do not claim one-time installation permission, QR scanning, XHTTP, kill switch, automatic reconnect or guaranteed crash cleanup. Domain routes work through IPv4 DNS answers; URL paths cannot be separated and shared CDN IPs cannot be isolated by hostname. Reject default-route takeover and conflicting destination routes; overlapping VPN-assigned subnets are unsupported.

The server library and dashboard connections have separate lifecycles. Bulk library deletion keeps existing connections. Saved server/group destination rules apply when choosing a server. Protocol latency results are not interchangeable: TCP reachability does not prove a working proxy.

Use focused tests listed in `docs/DEVELOPMENT.md`. UI/IPC fixtures must remain synthetic and must not contact the real helper. Read-only diagnosis can use current state, but preserve live connections during edits/builds. Validate the source and packaged artifact for private data before sharing. No personal data belongs in docs, test fixtures, Git history or app bundles. Keep real runtime state in Application Support/Keychain.

When reporting work, distinguish source changes, built installers, installed version and actually running version. State which checks passed and whether a real VPN connection was tested. Update the concise handoff when behavior or outstanding work changes.
