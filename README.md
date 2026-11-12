# Mochi

<img src="assets/mochi-256.png" alt="Mochi icon" width="120">

**A macOS VPN dashboard for separate projects, servers and destination rules.**

Apple Silicon · macOS 13+ · MVP 0.18.1

Mochi (もち) is a macOS app for separate VPN connections and destination rules. The project was renamed from TunnelDesk at version 0.18.0. Current release: 0.18.1. Repository: [rozaliyari/Mochi](https://github.com/rozaliyari/Mochi). The public interface is English and follows the system appearance.

## Features

- Up to 10 independent OpenVPN or VLESS/VMess connections, with dashboard and menu-bar controls.
- OpenVPN file import or manual server setup. Named connections can be removed individually.
- Login setup at import time; optional password and encrypted-key storage in macOS Keychain. Separate fresh 2FA challenge entry; optional manual TOTP setup-key entry.
- Named, collapsible server-library groups; multi-file, clipboard, Base64, JSON and HTTPS subscription import. Batch library deletion and destination assignment. TCP and HTTPS tests.
- IPv4 CIDRs, domains, URLs and DIRECT rules. URL IP destinations become /32 routes; paths, ports and query strings cannot be routed separately.
- Bundled Apple Silicon release with runtime and connection engines; local development can use Homebrew dependencies.

## Run from source

On macOS with Homebrew, run `brew install openvpn python-tk@3.13 sing-box`, then double-click `Start Mochi.command`. Source execution may show Terminal and requires administrator authentication for the network helper. Recipients of the portable app need no Python or Homebrew.

To create a development app: `python3 tools/build_macos_app.py /new/path/Mochi.app`. See `docs/PORTABLE-BUILD.md` for the self-contained release.

## Daily use

Import an .ovpn file and save login details in Login settings. Login password and Private Key Password are separate values; the app labels the latter Private key password. For phone 2FA, select Two-step and leave the optional Authenticator setup-key feature off. Add destinations, then turn on. Add subscriptions in the server library, select a group or rows to set destinations, then select one supported server to create or switch a dashboard connection. Switching an active connection requires disconnecting it first.

Closing the dashboard hides it; the menu-bar icon keeps working. Quit disconnects the app's tunnels. A normal cleanup is supported; crash cleanup is not guaranteed.

## Limits

IPv4 only. No kill switch or automatic reconnect. One foreground privileged helper per app namespace. Administrator authentication can recur on service startup; a one-time privileged installer is not implemented. Keychain permission is separate; successful reads are cached per connection for the current process, and Always Allow is controlled by macOS. QR scanning is disabled. XHTTP is unsupported; VLESS/VMess transports are TCP, WebSocket, gRPC and HTTPUpgrade. Arbitrary V2Ray/Xray configs are not executed. Library limit: 500 servers; dashboard limit: 10.

Overlapping destinations across connections are rejected; overlapping interface-assigned VPN subnets remain unsupported. Domain routing uses resolved IPv4 addresses and cannot distinguish sites sharing an IP. DNS-over-HTTPS, cached connections and IPv6 can bypass this approach. Do not infer VPN protocol support from a successful TCP latency result.

## Privacy and distribution

This source tree contains no personal connection exports, credentials, subscription URLs, server settings, logs or Git history from the previous workspace. Test fixtures use synthetic credentials and example/public test addresses. New Mochi releases use a separate preferences directory, Keychain service, helper namespace and bundle identifier; existing TunnelDesk data is not migrated automatically.

Build inputs and third-party licenses are documented in `docs/PORTABLE-BUILD.md`. No project reuse license has been selected. Releases are locally ad-hoc signed, not notarized. No Developer ID identity is configured on this build machine.

Start with `docs/PROJECT_GUIDE.md` for architecture and `docs/AI_HANDOFF.md` for the next development step. The project skill is `.agents/skills/mochi-development/SKILL.md`.
