# Project guide

## Architecture and boundaries

The native Objective-C launcher starts an unprivileged Python/Tk dashboard and a foreground privileged helper through the macOS administrator dialog. The helper owns OpenVPN/sing-box processes, destination routes and DNS resolver files. Owner-only Unix sockets connect launcher, dashboard and helper. The dashboard publishes bounded, non-secret connection state for the menu bar. No credentials pass through menu IPC.

## Source map

- `native/Launcher.m`: application lifecycle, service startup, status icon, per-connection switches and dashboard IPC.
- `app.py`: profile cards, login settings, saved credential reuse, status polling and challenge dialogs.
- `profiles.py`, `settings.py`: public identity/version/limits and private preferences schema.
- `keychain.py`, `auth.py`: exact-item Keychain storage, session cache, config binding, password validation and TOTP.
- `management.py`: OpenVPN management channel, encrypted-key and server challenge responses.
- `helper.py`: privileged sessions, route ownership, endpoint exclusions, process monitoring and cleanup.
- `core.py`, `server_profile.py`: OpenVPN allowlist, route validation and manual profile construction.
- `dns_rules.py`: validated DNS forwarding, split-resolver ownership and recovery journal.
- `subscriptions.py`: bounded HTTPS download, safe outbound reconstruction, protocol import and latency checks.
- `subscription_ui.py`: group library, batch import/removal, destinations and asynchronous tests.
- `tray_control.py`: owner-only dashboard IPC and non-secret state snapshots.
- `runtime_paths.py`, `desktop_launch.py`, `desktop_bootstrap.py`, `launch.py`: packaged paths, startup, discovery and shutdown.
- `ui_widgets.py`, `dialogs.py`: system theme, paste-enabled inputs, URL normalization and Tk-compatible dialogs.
- `tools/`: portable dependencies, build/signing/audit, source checks and local reset tools.
- `tests/`: synthetic unit tests and isolated UI/IPC checks.

## Data model

Preferences are in `~/Library/Application Support/Mochi/`. Profiles include name, engine, file path, username, auth mode, credential identifier, remember opt-in, server override and destination rules. Passwords are absent from preferences. Keychain items belong to `com.mochi.saved-logins` and are bound to the sanitized VPN profile. Session caching returns copies, updates after successful writes and invalidates on Forget. External Keychain edits may not be visible until process restart.

The private server library uses `subscription-cache.json`: rows hold a sanitized outbound or an unsupported-row error, name, latency results, optional group ID/name and optional destination rules. Library groups are independent of dashboard connections. Deleting a library group does not remove connections already created from it. Group rule edits apply when choosing a server, not retroactively to running tunnels. New imported groups append; source URLs are not persisted for automatic refresh. Temporary provider profiles belong only in Application Support.

## Authentication

A fixed-password connection can reuse its saved username/password and optional encrypted-key password. Two-step mode can have an optional initial login password, an encrypted-key password and a later server challenge. These values are distinct. A VPN key password is not a TOTP setup seed. Current 2FA responses are never persisted. Errors such as bad decrypt, AUTH_FAILED and account already active describe different stages; inspect a current redacted log before diagnosing.

## Routing

Imported and server default routes are filtered. The helper uses explicit destination routes and disables engine automatic route/DNS takeover. Broad routes are split around transport endpoints; exact endpoint routes remain rejected. Destinations shared across different tunnels and incompatible DIRECT rules fail. A URL's hostname/IP becomes a routing rule; HTTP path/query selection is not implemented. Domain routing waits for route installation before returning validated DNS A records. Resolver journals support recovery without overwriting unrelated files.

## Release workflow

Use `docs/PORTABLE-BUILD.md` for dependency acquisition, redistribution sources and artifact audit. The basic app builder alone is not portable. Portable releases embed the interpreter, Tcl/Tk, OpenVPN and sing-box. Build outputs must be outside tracked source. Build/sign/audit before distributing. A new signature or app identity can cause macOS and Keychain to request permission again.

The Mochi source rename intentionally isolates personal TunnelDesk state. Do not auto-import old secrets. The previous app can remain active during source/build work; do not run both helpers against real routes for an acceptance test.

## Known work

- Implement a securely installed privileged service to avoid repeated administrator startup prompts; current foreground helper is not that service.
- Improve labels and field-specific validation for login password versus encrypted-key password.
- Add XHTTP through a separately evaluated compatible engine; do not silently map it to another transport.
- QR scanning remains disabled; no QR support claim until implemented and tested.
- Add subscription-group refresh with explicit source storage consent and merge semantics.
- Verify real multi-tunnel operation and older macOS hardware independently; unit tests do not establish those results.
- Improve crash/orphan cleanup and reconnect policy, with explicit 2FA semantics.

## Branding and artwork

The application is Mochi (もち), named for the Japanese confection. `assets/Mochi.icns` is the application icon; `assets/mochi-status.png` is the native template menu icon. `tools/draw_icon.m` contains reproducible vector artwork using public AppKit drawing APIs. Compile with `clang -O2 -fobjc-arc -fno-modules -framework AppKit -framework Foundation tools/draw_icon.m -o /tmp/mochi-draw-icon`, then run `/tmp/mochi-draw-icon assets`. Create an iconset from the generated 16–1024 pixel PNGs and use `iconutil -c icns` to regenerate the app icon. The app builder copies both assets and sets CFBundleIconFile.

The distributable reuses the previously audited Python/Tcl/Tk/OpenVPN/sing-box binaries; only application source, native launcher, icons and identity metadata changed. Original bundled third-party source archives and licenses accompany the release. The portable build script remains the reproducible route with freshly downloaded official inputs.
