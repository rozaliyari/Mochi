# Development

Python 3.10+ is required for source. Native UI, Keychain and packaging need macOS; unit tests also run on Linux.

```sh
python3 -m unittest discover -s tests -q
python3 tests/smoke_local.py
python3 tests/smoke_subscriptions.py
python3 tests/smoke_redesign.py
python3 tools/check_public_tree.py
```

UI smoke tests use temporary profiles, synthetic credentials and mocked network actions. They do not start real VPNs. `tests/smoke_keychain.py` creates a random dummy Keychain item and can show a macOS permission dialog; it is not part of routine validation. Native menu IPC checks use `tests/smoke_tray.py --native-check /path/to/Mochi.app/Contents/MacOS/Mochi` and fake connection state.

See `PROJECT_GUIDE.md` for source responsibilities, `SECURITY.md` before auth/routing changes, and `PORTABLE-BUILD.md` before release work. The private repository is https://github.com/rozaliyari/Mochi. Stage only clean source and docs; run the publication check before publishing. Do not include runtime caches, profiles, secret links, generated artifacts or user logs.
