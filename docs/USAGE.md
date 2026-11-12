# Mochi

1. Drag Mochi.app to Applications and open it.
2. Approve the macOS request with your Mac administrator password. It is not your VPN password.
3. Select **Import .ovpn file** for OpenVPN, or **Set up server manually** when your provider gave you its certificates and server details.
4. Add a domain, IPv4 address or URL, then select **Turn on**. `http://203.0.113.10/luna/` routes the whole IP (`203.0.113.10/32`); paths cannot be routed separately.

Use the network icon in the menu bar for each connection name and its On/Off control. Keep Mochi there to avoid another Mac password request during the same session.
**Open dashboard** shows the window. Closing it hides it. **Quit Mochi** disconnects all its tunnels and exits.

For two-step profiles, select **Save login in Mac Keychain** and enter username plus VPN access key once. Later connections ask for the fresh 2FA code. Phone codes are never saved. QR scanning is deferred; manual setup-key and code entry remain available.

Requires Apple Silicon and macOS 13+. The portable app includes its dependencies. The build is ad-hoc signed, not Apple-notarized.
