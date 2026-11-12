"""Package the clean app, matching public sources, notices and Persian setup."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
from audit_portable_macos import audit
from build_portable_macos import ROOT,CACHE
from settings import VERSION


def package(app,folder,dmg):
    app=pathlib.Path(app).resolve();folder=pathlib.Path(folder).resolve();dmg=pathlib.Path(dmg).resolve()
    if folder.exists() or dmg.exists():raise RuntimeError('Choose fresh release output paths')
    report=audit(app)
    if not report['passed']:raise RuntimeError('Artifact audit must pass before packaging')
    folder.mkdir(parents=True)
    shutil.copytree(app,folder/'Mochi.app',symlinks=True)
    (folder/'Applications').symlink_to('/Applications',target_is_directory=True)
    sources=folder/'Sources';sources.mkdir()
    code=sources/'Mochi';code.mkdir()
    files=[pathlib.Path(p) for p in subprocess.check_output(['git','ls-files','-z'],cwd=ROOT).decode().split('\0') if p]
    for relative in files:
        destination=code/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/relative,destination)
    for name in ('tunnelblick-10.0.2-source.tar.gz','sing-box-1.14.4-source.tar.gz','sing-box-build-info.txt','GPL-3.0.txt'):
        shutil.copy2(CACHE/name,sources/name)
    shutil.copy2('/opt/homebrew/Cellar/go@1.26/1.26.10/LICENSE',sources/'Go-LICENSE.txt')
    def public_header(info):
        info.uid=0;info.gid=0;info.uname='root';info.gname='wheel';info.mtime=0
        return info
    with tarfile.open(sources/'go-module-sources.tar.gz','w:gz',compresslevel=5) as archive:
        cache=ROOT/'build/go-modules/cache/download'
        for file in sorted(cache.rglob('*')):
            if file.is_file() and not file.name.endswith(('.lock','.tmp','.partial')):
                archive.add(file,arcname=str(pathlib.Path('cache/download')/file.relative_to(cache)),recursive=False,filter=public_header)
    (folder/'START-HERE.txt').write_text(f'''Mochi {VERSION}

Apple Silicon · macOS 13+

1. Drag Mochi.app to Applications.
2. Open it and approve the macOS permission request.
3. Import your own profile or subscription. Add websites, then turn on.

Use the menu-bar network icon for on/off controls.
Closing the window hides it. Quit disconnects all connections and exits.

No personal profiles, passwords, subscriptions or logs are included.
No separate Python or Homebrew installation is required.
This build is not Apple-notarized; macOS may require a trust decision.
IPv4 only. No kill switch. Overlapping routes are rejected.
Source and licenses are in Sources.
''')
    (folder/'verification.json').write_text(json.dumps(report,indent=2))
    checks=[]
    for file in sorted(sources.iterdir()):
        if file.is_file():checks.append(hashlib.sha256(file.read_bytes()).hexdigest()+'  Sources/'+file.name)
    (folder/'SHA256SUMS.txt').write_text('\n'.join(checks)+'\n')
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(folder/'Mochi.app')],check=True)
    subprocess.run(['/usr/bin/hdiutil','create','-volname','Mochi','-srcfolder',str(folder),'-format','UDZO','-imagekey','zlib-level=6',str(dmg)],check=True)
    checksum=hashlib.sha256(dmg.read_bytes()).hexdigest()
    dmg.with_suffix('.dmg.sha256').write_text(checksum+'  '+dmg.name+'\n')
    print('Created clean installer image:',dmg)


if __name__=='__main__':package(*sys.argv[1:4])
