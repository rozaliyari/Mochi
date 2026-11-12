"""Explicit local uninstall/reset. Original VPN exports and other VPN apps stay."""
import ctypes as C
import fcntl
import json
import os
import pathlib
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def stop_helpers():
    for path in pathlib.Path('/var/run').glob('mochi-*/control.sock'):
        try:
            if path.stat().st_uid not in (0,os.getuid()):continue
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(3);client.connect(str(path));client.sendall(b'{"op":"shutdown"}\n');client.recv(4096)
        except OSError:pass


def erase(path):
    path=pathlib.Path(path)
    if path.is_symlink():path.unlink();return 1
    if path.is_dir():shutil.rmtree(path);return 1
    if path.exists():path.unlink();return 1
    return 0


def clear_keychain():
    from keychain import NativeKeychain,SERVICE
    backend=NativeKeychain()
    query=backend.cf.CFDictionaryCreateMutable(None,0,None,None)
    service=backend.cf.CFStringCreateWithCString(None,SERVICE.encode(),0x08000100)
    if not query or not service:raise RuntimeError('Cannot create scoped credential reset')
    try:
        backend.cf.CFDictionarySetValue(query,backend.constant('kSecClass'),backend.constant('kSecClassGenericPassword'))
        backend.cf.CFDictionarySetValue(query,backend.constant('kSecAttrService'),service)
        backend.cf.CFDictionarySetValue(query,backend.constant('kSecMatchLimit'),backend.constant('kSecMatchLimitAll'))
        status=backend.sec.SecItemDelete(query)
        if status not in (0,-25300):backend.check(status)
        status=backend.sec.SecItemCopyMatching(query,None)
        if status!=-25300:raise RuntimeError('Mochi credential removal could not be verified')
    finally:backend.cf.CFRelease(query);backend.cf.CFRelease(service)


def user_reset():
    if os.geteuid()==0:raise RuntimeError('Run the user reset from the normal account')
    stop_helpers()
    lines=subprocess.check_output(['/bin/ps','-axo','uid=,pid=,command='],text=True).splitlines()
    for line in lines:
        parts=line.strip().split(None,2)
        if len(parts)!=3 or parts[0]!=str(os.getuid()):continue
        if '/Mochi.app/Contents/' in parts[2] and '/desktop_launch.py ' in parts[2]:
            try:os.kill(int(parts[1]),signal.SIGTERM)
            except ProcessLookupError:pass
    time.sleep(1)
    # An old controller is also part of this project's prototypes.
    for line in subprocess.check_output(['/bin/ps','-axo','uid=,pid=,command='],text=True).splitlines():
        parts=line.strip().split(None,2)
        if len(parts)!=3 or parts[0]!=str(os.getuid()):continue
        if parts[2].startswith(('/Applications/Mochi.app/Contents/MacOS/Mochi','/Applications/MultiVPN Control.app/Contents/MacOS/')):
            try:os.kill(int(parts[1]),signal.SIGTERM)
            except ProcessLookupError:pass
    clear_keychain()
    home=pathlib.Path.home();removed=0
    for path in [home/'Library/Application Support/Mochi',home/'Library/Application Support/MultiVPN Control',
                 home/'Desktop/Mochi.app',pathlib.Path('/Applications/Mochi.app'),pathlib.Path('/Applications/MultiVPN Control.app')]:
        try:removed+=erase(path)
        except PermissionError:pass  # Administrator phase removes system installs.
    for base in ('Preferences','Caches','Logs','Saved Application State'):
        parent=home/'Library'/base
        for pattern in ('local.mochi.dashboard*','com.mochi*','local.multivpn.public.controller*'):
            for path in parent.glob(pattern):removed+=erase(path)
    for parent in [home/'Documents/Codex',home/'Desktop']:
        for path in parent.glob('Mochi*'):
            if path==ROOT or path==ROOT.parent:continue
            # Preserve a newly built clean installer only in the final phase.
            if path.suffix in ('.zip','.dmg','.sha256') or path.name.startswith(('Mochi-0.10.','Mochi-0.11.')):
                removed+=erase(path)
    outputs=home/'Documents/Codex/2026-10-30/referenced-chatgpt-conversation-this-is-an-2/outputs'
    if outputs.is_dir():
        for path in outputs.glob('Mochi*'):removed+=erase(path)
    for path in pathlib.Path('/private/tmp').glob('mochi-ui-*'):
        try:
            if path.lstat().st_uid==os.getuid():removed+=erase(path)
        except FileNotFoundError:pass
    print(json.dumps(dict(user_reset=True,keychain_cleared=True,items_removed=removed)))


def system_reset(uid):
    if os.geteuid()!=0 or uid<1:raise RuntimeError('Requires the administrator cleanup flow')
    stop_helpers()
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        live=False
        for path in pathlib.Path('/var/run').glob('mochi-*/control.sock'):
            try:
                with socket.socket(socket.AF_UNIX) as client:
                    client.settimeout(.1);client.connect(str(path));live=True
            except OSError:pass
        if not live:break
        time.sleep(.2)
    if live:raise RuntimeError('A Mochi service is still running')
    lock=pathlib.Path('/var/run/mochi.lock');fd=None
    if lock.exists():
        fd=os.open(lock,os.O_RDWR|os.O_NOFOLLOW)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:
        from dns_rules import ResolverFiles
        journal=pathlib.Path('/var/run/mochi-dns.json')
        if journal.exists():ResolverFiles(journal=str(journal)).recover()
        removed=0
        for path in pathlib.Path('/var/run').glob('mochi-*'):
            if path.lstat().st_uid==0:removed+=erase(path)
        if lock.exists():removed+=erase(lock)
        for path in ('/Applications/Mochi.app','/Applications/MultiVPN Control.app'):
            removed+=erase(path)
        print(json.dumps(dict(system_reset=True,items_removed=removed)))
    finally:
        if fd is not None:os.close(fd)


if __name__=='__main__':
    if sys.argv[1:]==['--user']:user_reset()
    elif len(sys.argv)==3 and sys.argv[1]=='--system':system_reset(int(sys.argv[2]))
    else:raise SystemExit('Use --user or --system UID')
