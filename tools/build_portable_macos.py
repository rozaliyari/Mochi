"""Create a clean Apple Silicon app using official runtime/engine inputs.

No path under the user's Application Support, Downloads or Keychain is copied.
"""
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from build_macos_app import build,ROOT

CACHE=ROOT/'build'/'portable-inputs'
PYTHON_SOURCE=CACHE/'python-expanded/Python_Framework.pkg/Payload'
PYTHON_PREFIX='/Library/Frameworks/Python.framework'
MAGIC={b'\xfe\xed\xfa\xce',b'\xce\xfa\xed\xfe',b'\xfe\xed\xfa\xcf',b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe',b'\xbe\xba\xfe\xca',b'\xca\xfe\xba\xbf'}


def run(args,**kwargs):
    return subprocess.run(list(map(str,args)),check=True,capture_output=True,text=True,**kwargs).stdout


def macho(path):
    if not path.is_file() or path.is_symlink():return False
    with path.open('rb') as stream:return stream.read(4) in MAGIC


def ignore(directory,names):
    return [name for name in names if name in ('__pycache__','site-packages','test','tests','idlelib','turtledemo','ensurepip','Headers','PrivateHeaders','include','bin','pkgconfig','Python.app','_CodeSignature') or name.endswith(('.pyc','.pyo','.a','Config.sh')) or name.startswith('config-')]


def relocate(contents):
    paths=[path for path in contents.rglob('*') if macho(path)]
    for path in paths:
        path.chmod(path.stat().st_mode|0o200)
        arches=run(['/usr/bin/lipo','-archs',path]).split()
        if 'arm64' not in arches:raise RuntimeError('Non-Apple-Silicon code in '+str(path.relative_to(contents)))
        if len(arches)>1:
            temporary=path.with_name(path.name+'.arm64')
            run(['/usr/bin/lipo',path,'-thin','arm64','-output',temporary]);temporary.replace(path)
        subprocess.run(['/usr/bin/codesign','--remove-signature',str(path)],capture_output=True)
        dependencies=run(['/usr/bin/otool','-L',path]).splitlines()[1:]
        for line in dependencies:
            dependency=line.strip().split(' (compatibility',1)[0]
            if dependency.startswith(PYTHON_PREFIX):
                mapped=contents/'Frameworks/Python.framework'/dependency.removeprefix(PYTHON_PREFIX+'/')
                if not mapped.exists():raise RuntimeError('Missing runtime dependency '+dependency)
                replacement='@loader_path/'+os.path.relpath(mapped,path.parent)
                run(['/usr/bin/install_name_tool','-change',dependency,replacement,path])
            elif dependency.startswith(('/opt/','/usr/local/','/Users/')):
                raise RuntimeError('External runtime dependency refused: '+dependency)
        ids=run(['/usr/bin/otool','-D',path]).splitlines()[1:]
        if ids:run(['/usr/bin/install_name_tool','-id','@loader_path/'+path.name,path])
        commands=run(['/usr/bin/otool','-l',path])
        for rpath in re.findall(r'cmd LC_RPATH\n\s+cmdsize \d+\n\s+path (.*?) \(offset',commands):
            if rpath.startswith('/') and not rpath.startswith(('/System/','/usr/lib/')):
                run(['/usr/bin/install_name_tool','-delete_rpath',rpath,path])
    for path in sorted(paths,key=lambda p:len(p.parts),reverse=True):
        if path==contents/'MacOS/Mochi':continue
        run(['/usr/bin/codesign','--force','--sign','-',path])
    # Seal nested frameworks/app resources after their Mach-O children.
    for framework in sorted(contents.rglob('*.framework'),key=lambda p:len(p.parts),reverse=True):
        run(['/usr/bin/codesign','--force','--sign','-',framework])
    return paths


def portable(destination):
    destination=pathlib.Path(destination).resolve()
    if not PYTHON_SOURCE.is_dir():raise RuntimeError('Extract the verified official Python installer first')
    vendor=pathlib.Path('/Applications/Tunnelblick.app')
    run(['/usr/bin/codesign','--verify','--deep','--strict',vendor])
    openvpn=vendor/'Contents/Resources/openvpn/openvpn-2.7.8-openssl-3.5.9/openvpn'
    singbox=CACHE/'sing-box-compatible'
    if not singbox.is_file():raise RuntimeError('Build the compatible sing-box engine first')
    build(destination)
    contents=destination/'Contents';framework=contents/'Frameworks/Python.framework'
    shutil.copytree(PYTHON_SOURCE,framework,symlinks=True,ignore=ignore)
    runtime=contents/'MacOS/MochiRuntime'
    shutil.copy2(PYTHON_SOURCE/'Versions/3.14/Resources/Python.app/Contents/MacOS/Python',runtime)
    helper=contents/'Helpers';helper.mkdir(exist_ok=True)
    shutil.copy2(openvpn,helper/'openvpn');shutil.copy2(singbox,helper/'sing-box')
    resources=contents/'Resources/Runtime';resources.mkdir()
    for source,name in [('Tcl','tcl'),('Tk','tk')]:
        base=PYTHON_SOURCE/'Versions/3.14/Frameworks'/(source+'.framework')/'Versions/9.0/Resources'
        shutil.copytree(base/'Scripts',resources/name,symlinks=True)
        if (base/'tcl9').is_dir():shutil.copytree(base/'tcl9',resources/'tcl9',dirs_exist_ok=True)
    licenses=contents/'Resources/ThirdParty';licenses.mkdir()
    shutil.copy2(CACHE/'cacert.pem',resources/'cacert.pem')
    shutil.copy2(CACHE/'certifi-LICENSE.txt',licenses/'certifi-LICENSE.txt')
    shutil.copy2(CACHE/'ca-source.json',licenses/'ca-source.json')
    shutil.copy2(vendor/'Contents/Resources/COPYING',licenses/'OpenVPN-GPL-2.txt')
    source=CACHE/'sing-box-source/sing-box-1.14.4'
    shutil.copy2(source/'LICENSE',licenses/'sing-box-GPL-3.txt')
    notes='''Third-party components

Python 3.14.10 and bundled OpenSSL/Tcl/Tk: official python.org macOS installer.
Original license texts remain in the embedded Python/Tcl/Tk framework resources.
OpenVPN 2.7.8 / OpenSSL 3.5.9: the signed Tunnelblick 10.0.2 (build 6590) engine.
Its matching source, build scripts and patches are supplied in the adjacent Sources folder.
sing-box 1.14.4: compiled from the official source with Go 1.26, CGO disabled,
and with_gvisor,with_utls,with_quic tags. VLESS and VMess are included; Naive is not.
certifi: public Mozilla CA certificates from the pinned official GitHub source commit.
No personal VPN exports, server subscriptions, passwords or Keychain items are bundled.
'''
    (licenses/'NOTICES.txt').write_text(notes)
    info=plistlib.loads((contents/'Info.plist').read_bytes())
    info['LSMinimumSystemVersion']='13.0'
    info['CFBundleDisplayName']='Mochi';info['CFBundleName']='Mochi'
    info['MochiPortable']=True
    (contents/'Info.plist').write_bytes(plistlib.dumps(info))
    paths=relocate(contents)
    for path in contents.rglob('*'):
        if path.is_symlink() and not path.resolve().is_relative_to(contents):
            raise RuntimeError('External symlink in packaged runtime')
    manifest=dict(architecture='arm64',minimum_macos='13.0',runtime='Python 3.14.10',openvpn='2.7.8 / OpenSSL 3.5.9',sing_box='1.14.4',personal_data_included=False,
                  engines={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in helper.iterdir()},macho_files=len(paths))
    (contents/'Resources/build-manifest.json').write_text(json.dumps(manifest,indent=2))
    run(['/usr/bin/codesign','--force','--deep','--sign','-',destination])
    run(['/usr/bin/codesign','--verify','--deep','--strict',destination])
    print('Portable Apple Silicon app built:',destination,flush=True)


if __name__=='__main__':portable(sys.argv[1])
