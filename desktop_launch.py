"""Unprivileged native-app companion; never reads the Mac administrator password."""
import json
import os
import pathlib
import signal
import subprocess
import sys
from app import rpc
from settings import VERSION
from runtime_paths import python_command,runtime_environment


def probe():
    for path in pathlib.Path('/var/run').glob('mochi-*/control.sock'):
        try:
            if path.parent.stat().st_uid!=0 or path.stat().st_uid!=os.getuid():continue
            info=rpc(str(path),{'op':'info'})
        except (OSError,RuntimeError,ValueError):continue
        # Only identify our exact app.py command and this helper socket. Never
        # activate or terminate another unrelated Python application.
        result=subprocess.run(['/bin/ps','-axo','pid=,command='],capture_output=True,text=True,check=True)
        for line in result.stdout.splitlines():
            parts=line.strip().split(None,1)
            if len(parts)==2 and '/app.py ' in parts[1] and parts[1].rstrip().endswith(str(path)):
                return dict(pid=int(parts[0]),socket=str(path),version=info.get('version'))
        return dict(socket=str(path),version=info.get('version'))
    return dict(version=VERSION)


def run(path):
    child=None
    def stop(*args):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop)
    try:
        child=subprocess.Popen(python_command(pathlib.Path(__file__).with_name('app.py'),path),env=runtime_environment())
        return child.wait()
    except KeyboardInterrupt:return 0
    finally:
        try:rpc(path,{'op':'shutdown'})
        except (OSError,RuntimeError):pass
        if child and child.poll() is None:
            child.terminate()
            try:child.wait(10)
            except subprocess.TimeoutExpired:child.kill();child.wait()


if __name__=='__main__':
    if sys.argv[1:]==['--probe']:print(json.dumps(probe()))
    elif len(sys.argv)==2:sys.exit(run(sys.argv[1]))
    else:sys.exit(2)
