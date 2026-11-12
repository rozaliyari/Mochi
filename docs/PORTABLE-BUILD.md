# Portable Apple Silicon release

The portable build targets macOS 13+ on arm64. All Mach-O load commands are checked; the native launcher and static vendor OpenVPN engine require 13.0, the rebuilt sing-box engine requires 12.0, and the official Python runtime supports older Apple Silicon systems. The package was executed on the build Mac; actual macOS 13 hardware/VM testing has not been performed.

## Public inputs

- Python 3.14.10 official universal2 macOS installer from python.org, verified against the release SHA-256. The package is expanded without running its installer scripts. Only the runtime is retained and its Mach-O code is thinned to arm64.
- OpenVPN 2.7.8 with OpenSSL 3.5.9 from the signature-verified Tunnelblick 10.0.2 (build 6590) app. Only the static OpenVPN executable is copied; no Tunnelblick profiles, preferences or user data are read.
- sing-box 1.14.4 official source archive, SHA-256 pinned. Built using Go 1.26.10 with CGO disabled and `with_gvisor,with_utls,with_quic`. This avoids the newer-macOS Cronet dependency. VLESS, VMess, TLS/Reality, WS and gRPC remain available. Naive proxy is outside this product's supported protocols.
- Public certifi CA certificates and license from a pinned commit in the official certifi GitHub repository; Git blob hashes are verified.

All runtime library references are rewritten to internal `@loader_path` locations. No external `/opt/homebrew`, `/usr/local` or Python framework dependency is allowed. The runtime disables user site packages and bytecode writes. The GUI executable lives under Mochi.app/Contents/MacOS, so macOS identifies the GUI as Mochi instead of Python/Python Launcher.

## Build

The build machine needs Apple command-line tools, Python 3.13+ for the build scripts, Go 1.26 and the official Tunnelblick 10.0.2 app. Recipients need none of these tools.

1. Run `python3 tools/fetch_portable_inputs.py`.
2. Expand `build/portable-inputs/python-3.14.10.pkg` with `pkgutil --expand-full` to `build/portable-inputs/python-expanded`.
3. Run `python3 tools/build_singbox_compatible.py`. If the public Go proxy refuses an individual pinned module, fetch that module with `GOPROXY=direct go mod download`; go.sum verification remains enabled.
4. Run `python3 tools/build_portable_macos.py /new/output/Mochi.app`.
5. Run `python3 tools/audit_portable_macos.py /new/output/Mochi.app` and `python3 tools/smoke_portable_macos.py /new/output/Mochi.app`.

The audit reads local profile/subscription identifiers only to detect accidental leakage, never prints matched values, and never exports Keychain items. The clean-launch smoke test uses a temporary HOME/settings directory and mocks the VPN RPC, so it cannot connect a real tunnel or change DNS/routes.

Matching engine sources, patches and build instructions accompany the distributable in Sources. Third-party licenses remain inside the app and source archives. Developer ID signing/notarization is not configured; the current package has a valid local ad-hoc signature and macOS may block an Internet-transferred copy pending a user's trust decision. Do not disable Gatekeeper as part of installation.

## Scope of verification

Verified: embedded GUI branding, a fresh empty profile, runtime/engine location isolation, public CA availability, engine version commands, application unit tests under the embedded Python, Mach-O architecture/minimum-OS/load-path checks and a complete app signature check. Live VPN authentication/TUN routing on a colleague's clean Mac still depends on their provider settings and has not been tested by this packaging check. Existing IPv4-only, overlapping-route, DNS/DoH and no-kill-switch limitations remain.
