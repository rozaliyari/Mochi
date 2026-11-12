"""Read-only artifact checks; matched private values are never printed."""
import json
import os
import pathlib
import re
import subprocess
import sys
from build_portable_macos import macho


def audit(app):
    app=pathlib.Path(app).resolve();contents=app/'Contents'
    issues=[];count=0;highest=(0,0)
    private=pathlib.Path.home()/'Library/Application Support/Mochi'
    markers={str(pathlib.Path.home()).encode()}
    prefs=private/'profiles.json'
    if prefs.exists():
        for row in json.loads(prefs.read_text()):
            for field in ('username','credential_id','path'):
                value=row.get(field,'')
                if value and len(value)>=6:markers.add(value.encode())
            for value in row.get('domains','').split(','):
                if value.strip():markers.add(value.strip().encode())
    cache=private/'subscription-cache.json'
    if cache.exists():
        for row in json.loads(cache.read_text()):
            value=row.get('outbound',{}).get('uuid')
            if value:markers.add(value.encode())
    for path in contents.rglob('*'):
        relative=str(path.relative_to(app))
        if path.is_symlink():
            if not path.exists() or not path.resolve().is_relative_to(app):issues.append('Unsafe symlink: '+relative)
            continue
        if not path.is_file():continue
        count+=1
        if path.name in ('profiles.json','direct.json','subscription-cache.json') or path.suffix in ('.ovpn','.p12','.pfx','.key','.log') or 'provider-profiles' in path.parts:
            issues.append('Personal/runtime file: '+relative)
        if path.suffix=='.pyc' or '__pycache__' in path.parts:issues.append('Mutable bytecode cache: '+relative)
        data=path.read_bytes()
        if any(marker in data for marker in markers):issues.append('Private marker: '+relative)
        if not macho(path):continue
        arch=subprocess.check_output(['/usr/bin/lipo','-archs',str(path)],text=True).strip()
        if arch!='arm64':issues.append('Unexpected architecture: '+relative)
        deps=subprocess.check_output(['/usr/bin/otool','-L',str(path)],text=True).splitlines()[1:]
        for line in deps:
            dep=line.strip().split(' (compatibility',1)[0]
            if dep.startswith(('/System/','/usr/lib/')):continue
            if dep.startswith('@loader_path/'):
                destination=(path.parent/dep.removeprefix('@loader_path/')).resolve()
                if destination.is_file() and destination.is_relative_to(app):continue
            issues.append('External/unresolved dependency: '+relative)
        build=subprocess.check_output(['/usr/bin/vtool','-show-build',str(path)],text=True)
        # Ignore compiler/linker version numbers inside LC_BUILD_VERSION.
        versions=re.findall(r'\bminos\s+(\d+\.\d+)',build)
        if not versions:versions=re.findall(r'\bversion\s+(\d+\.\d+)',build)[:1]
        for version in versions:
            current=tuple(map(int,version.split('.')));highest=max(highest,current)
            if current>(13,0):issues.append('Requires newer macOS than declared: '+relative)
    signature=subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],capture_output=True)
    if signature.returncode:issues.append('App signature validation failed')
    result=dict(files_checked=count,apple_silicon_only=True,minimum_macos='.'.join(map(str,highest)),
                no_private_markers=not any('Private marker' in value for value in issues),
                issues=issues,passed=not issues)
    print(json.dumps(result,indent=2))
    return result


if __name__=='__main__':sys.exit(0 if audit(sys.argv[1])['passed'] else 1)
