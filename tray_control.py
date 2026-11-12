"""Owner-only GUI control channel. Never transports passwords or challenge data."""
import json
import os
import pathlib
import queue
import re
import socketserver
import stat
import tempfile
import threading
import time


class TrayControl:
    def __init__(self,path):
        self.path=pathlib.Path(path)
        parent=self.path.parent
        info=parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('Unsafe menu control directory')
        if self.path.name!='control.sock' or self.path.exists() or self.path.is_symlink():raise ValueError('Unsafe menu control socket')
        self.commands=queue.Queue(maxsize=16);self.last_state=None;self.last_heartbeat=0
        owner=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    data=self.rfile.readline(2049)
                    if not data.endswith(b'\n') or len(data)>2048:raise ValueError()
                    message=json.loads(data)
                    if not isinstance(message,dict) or set(message)-{'op','id'}:raise ValueError()
                    if message.get('op') not in ('show','connect','disconnect'):raise ValueError()
                    if message['op']!='show':
                        if not isinstance(message.get('id'),str) or not re.fullmatch('[a-f0-9]{32}',message['id']):raise ValueError()
                    owner.commands.put_nowait(message)
                    reply={'ok':True}
                except (OSError,ValueError,TypeError,queue.Full):reply={'ok':False}
                self.wfile.write((json.dumps(reply)+'\n').encode())
        self.server=socketserver.UnixStreamServer(str(self.path),Handler)
        self.path.chmod(0o600)
        threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.1},daemon=True).start()

    def publish(self,profiles,busy=False):
        rows=[]
        for profile in profiles:
            rows.append({key:profile[key] for key in ('id','name','state')})
        data=json.dumps(dict(profiles=rows,busy=bool(busy)),ensure_ascii=False)
        if data==self.last_state:
            if time.monotonic()-self.last_heartbeat>=5:
                os.utime(self.path.with_name('state.json'),None);self.last_heartbeat=time.monotonic()
            return
        fd,name=tempfile.mkstemp(dir=self.path.parent)
        try:
            with os.fdopen(fd,'w') as stream:stream.write(data)
            os.replace(name,self.path.with_name('state.json'));self.last_state=data;self.last_heartbeat=time.monotonic()
        finally:
            if os.path.exists(name):os.unlink(name)

    def close(self):
        self.server.shutdown();self.server.server_close()
        self.path.unlink(missing_ok=True)
        self.path.with_name('state.json').unlink(missing_ok=True)
