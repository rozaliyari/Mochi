# Subscriptions

Open **Add VLESS / VMess**, paste an HTTPS subscription URL and load it.
Use TCP tests for reachability and HTTPS tests for actual tunnel verification.
Select a server and choose **Add selected server**. Add websites in its dashboard panel, then turn it on.

To change a server, turn its connection off first. Keep that connection selected when choosing the replacement.

Supported: VLESS with TLS/Reality, VMess AEAD, TCP, WebSocket, gRPC and HTTPUpgrade. Unsupported or insecure configurations are rejected. Full Xray JSON and XHTTP are not supported.

IPv4 only. No kill switch. Overlapping destinations are rejected. Browser DoH can bypass domain routing. See SECURITY.md.
# Group library (0.18)

Imports append named, collapsible groups instead of replacing the library. Import multiple files together, paste VLESS/VMess links or JSON from the clipboard, or load HTTPS subscriptions one at a time. The library holds up to 500 servers; the dashboard still supports up to 10 connections.

Select groups or multiple rows to remove them or set destination domains, URLs, IPv4 addresses and CIDRs. Removing library rows keeps existing dashboard connections. Use one selected server to create/switch a dashboard connection; saved destinations follow that server. Editing a group's destinations affects later selection, not an already running connection. Without saved group destinations, switching preserves the connection's existing rules.

XHTTP is unsupported by the bundled engine. Such rows may be imported for visibility but cannot be connected; TCP latency alone does not prove protocol compatibility. Supported transports remain TCP, WebSocket, gRPC and HTTPUpgrade. Arbitrary V2Ray/Xray engine configuration is not executed.

