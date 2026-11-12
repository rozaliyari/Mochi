#!/usr/bin/env python3
"""Start root helper, discover its socket automatically and run unprivileged UI."""
import pathlib, selectors, subprocess, sys, time
from app import rpc

base=pathlib.Path(__file__).resolve().parent
binary=sys.argv[1]
helper=subprocess.Popen(['/usr/bin/sudo','-n',sys.executable,str(base/'helper.py'),binary],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
path=None
try:
    sel=selectors.DefaultSelector(); sel.register(helper.stdout,selectors.EVENT_READ)
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        if not sel.select(timeout=1): continue
        line=helper.stdout.readline()
        if not line: raise RuntimeError('The VPN service could not start.')
        print(line,end='',flush=True)
        if line.startswith('Mochi socket: '): path=line.strip().split(': ',1)[1]; break
    sel.close()
    if not path: raise RuntimeError('Timed out starting the VPN service.')
    subprocess.run([sys.executable,str(base/'app.py'),path],check=True)
finally:
    if path:
        try: rpc(path,{'op':'shutdown'})
        except Exception: pass
    try: helper.wait(timeout=40)
    except subprocess.TimeoutExpired:
        print('The helper did not stop. Keep this Terminal open and inspect VPN processes.',file=sys.stderr)
    if helper.poll() is not None:
        print(helper.stdout.read(),end='')
