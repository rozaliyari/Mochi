# Mochi handoff

Version 0.18.1, renamed from TunnelDesk. Source is a clean standalone copy, with isolated Mochi app/runtime/preference/Keychain identifiers. No personal data was migrated. The existing installed TunnelDesk app and connections remain separate until the user switches to Mochi.

Completed: 0–10 profile cards, import/manual OpenVPN, saved fixed/key passwords, separate 2FA, per-process Keychain read cache, domains/IPv4 URLs/CIDRs/DIRECT, menu switches, system theme, VLESS/VMess library groups, bulk file/clipboard import, batch removal and destination assignment, TCP/HTTPS tests. Portable arm64 packaging exists with local ad-hoc signatures.

Read `PROJECT_GUIDE.md` for file map and architecture, `SECURITY.md` for trust boundaries, and `PORTABLE-BUILD.md` for release dependencies/licenses. Project skill: `.agents/skills/mochi-development/SKILL.md`.

Preserve user corrections: English UI, brief copy, paste-enabled inputs, meaningful names in sidebar/menu, credentials configured at import time, saved login reuse and only fresh 2FA entry on later logins where required. Login password, encrypted private-key password and TOTP seed are three separate things. IP URLs are destination routes, not VPN server overrides. Routing is by hostname/IP, not URL path. Do not misdiagnose generic auth failure as an incorrect phone code without evidence.

Remaining: one-time privileged service installation; better credential labels; disabled QR scanning; unsupported XHTTP; group refresh; no kill switch, auto reconnect or guaranteed crash cleanup. Overlapping tunnel subnets are unsupported. A selected library server carries saved destinations to the dashboard; removing library rows leaves existing connections.

Rename validation passed: 93 unit tests, synthetic login/group/menu checks, private metadata scan and clean bundled-runtime launch. Native Mochi app/menu icons are built from tools/draw_icon.m. Next step: user acceptance of the clean Mochi release; keep existing live tunnels running until the user switches. Do not claim fresh live VPN acceptance or one-time authorization based on local tests.

0.18.1: Login form now labels the encrypted-key field Private key password, separates Authenticator seed/code-generation wording, focuses the failing field and shows inline validation. Surrounding CR/LF from key paste is removed; spaces are preserved and interior line breaks are rejected. Synthetic UI regression passed; no real password or live server validation performed.

Repository: https://github.com/rozaliyari/Mochi (private). Source, artwork, docs and project skill are published; personal runtime data and installers remain outside Git tracking.
