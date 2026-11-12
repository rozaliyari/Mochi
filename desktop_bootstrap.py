"""Administrator-authenticated startup, invoked only by the native app launcher."""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
from runtime_paths import engine_paths,python_command,runtime_environment


def main():
    if os.geteuid()!=0 or len(sys.argv)!=4:raise RuntimeError('Invalid administrator launch')
    uid,watcher=int(sys.argv[1]),int(sys.argv[2])
    binary=sys.argv[3]
    if uid<1 or watcher<2 or binary not in engine_paths('openvpn'):
        raise RuntimeError('Invalid launch settings')
    owner=subprocess.run(['/bin/ps','-p',str(watcher),'-o','uid='],capture_output=True,text=True,check=True)
    if owner.stdout.strip()!=str(uid):raise RuntimeError('Launcher owner changed')
    folder=pathlib.Path(tempfile.mkdtemp(prefix='mochi-start-',dir='/var/run'))
    log=folder/'startup.log'
    fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    env=runtime_environment();env.update(SUDO_UID=str(uid),PATH='/usr/bin:/bin:/usr/sbin:/sbin')
    with os.fdopen(fd,'wb') as stream:
        process=subprocess.Popen(python_command(pathlib.Path(__file__).with_name('helper.py'),binary,watcher),
                                 stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,
                                 start_new_session=True,close_fds=True,env=env)
    deadline=time.monotonic()+25
    while time.monotonic()<deadline:
        for line in log.read_text(errors='replace').splitlines():
            if line.startswith('Mochi socket: '):
                print(line.split(': ',1)[1],flush=True);return
        if process.poll() is not None:
            raise RuntimeError('VPN service could not start. '+log.read_text(errors='replace')[-1500:])
        time.sleep(.1)
    process.terminate()
    try:process.wait(10)
    except subprocess.TimeoutExpired:process.kill();process.wait()
    raise RuntimeError('VPN service startup timed out')


if __name__=='__main__':main()
