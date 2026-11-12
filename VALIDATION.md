# Mochi 0.18.0 validation

- 93 unit tests passed after the complete source/identity rename.
- Synthetic login/2FA, subscription grouping/batch deletion/destinations UI checks passed.
- Native menu IPC check passed with mock connection actions; no live routes were changed.
- Clean portable launch passed under bundled Python 3.14.10 and Tk 9.0.4: application identity Mochi, one blank profile, packaged runtime/engines and CA trust.
- Artifact audit passed for 1,516 files: arm64 code, macOS 13 minimum, internal/system dependencies and no local private markers. Signature verification passed.
- Source publication check and scan against local profile usernames, credential IDs, paths, domains and remote endpoints passed without displaying matched data. Skill frontmatter validation passed.
- Application artwork was visually inspected. The menu icon is a monochrome template so macOS can adapt it to light/dark appearance.
- No real Mochi VPN connection, older-macOS device acceptance or notarization is claimed. Existing TunnelDesk tunnels were preserved during this work.
