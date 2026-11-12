#!/usr/bin/env python3
"""Catch common private-file leaks in tracked source; never print matched data."""
import pathlib,re,subprocess,sys
root=pathlib.Path(__file__).resolve().parents[1]
result=subprocess.run(['git','ls-files','-z'],cwd=root,capture_output=True)
if result.returncode:
    print('Initialize the Git repository and stage source files before checking.');sys.exit(2)
files=[root/p for p in result.stdout.decode().split('\0') if p]
blocked={'.ovpn','.pem','.key','.crt','.cer','.p12','.pfx','.log','.har'}
issues=[]
for path in files:
    relative=path.relative_to(root)
    if path.suffix.lower() in blocked or path.name in ('profiles.json','direct.json') or path.name.startswith(('subscription-cache','subscription-test-results','proxy-')) or path.name.startswith('.env') and path.name!='.env.example':
        issues.append(str(relative));continue
    if not path.is_file():continue
    data=path.read_bytes()
    # A real multiline PEM body is different from a dummy marker in source tests.
    if re.search(rb'(?m)^-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{64,}',data):
        issues.append(str(relative))
    if re.search(rb'(?m)^<key>\s*$',data):issues.append(str(relative))
if issues:
    print('Private material or runtime files must be removed from tracked source:')
    for name in sorted(set(issues)):print(' - '+name)
    sys.exit(1)
print(f'Publication check passed for {len(files)} tracked source/documentation files.')
