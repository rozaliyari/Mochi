"""Exercise actual tray IPC with a mock GUI; never contacts the VPN helper."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import tkinter as tk
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app
from profiles import FIELDS


def send(path,message):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3);client.connect(str(path));client.sendall((json.dumps(message)+'\n').encode())
        assert json.loads(client.makefile('rb').readline())['ok']


with tempfile.TemporaryDirectory(dir='/tmp',prefix='td-tray-test-') as folder:
    path=pathlib.Path(folder)/'control.sock'
    root=tk.Tk();errors=[];root.report_callback_exception=lambda kind,error,trace:errors.append(error)
    profiles=[dict(FIELDS,name=name,path='/unused-test-profile.json',engine='singbox',domains='*.example.test') for name in ('Example Work','Example Personal')]
    with patch.dict(os.environ,{'MOCHI_UI_SOCKET':str(path)}),patch.object(app,'PREFS',pathlib.Path(folder)/'profiles.json'),patch.object(app,'load',return_value=profiles),patch.object(app.App,'request'):
        desk=app.App(root,'/never-contact-real-helper.sock')
        root.title('Mochi menu test — no live VPN changes')
        root.update()
        def set_state(fields,state):
            name=fields['name'].get();desk.states[name]=dict(state=state,interface='',error='',dns_error='',log='');desk.render(desk.states)
        desk.connect=lambda fields:set_state(fields,'connected')
        desk.disconnect=lambda fields:set_state(fields,'disconnected')
        set_state(desk.cards[0]['fields'],'connected')
        one,two=[card['fields']['credential_id'].get() for card in desk.cards]
        send(path,dict(op='connect',id=two));desk.drain_tray();root.update()
        assert desk.states['Example Personal']['state']=='connected'
        assert desk.states['Example Work']['state']=='connected'
        send(path,dict(op='disconnect',id=two));desk.drain_tray();root.update()
        assert desk.states['Example Personal']['state']=='disconnected'
        assert desk.states['Example Work']['state']=='connected'
        desk.close();root.update();assert not root.winfo_viewable()
        send(path,dict(op='show'));desk.drain_tray();root.update();assert root.winfo_viewable()
        if '--preview' in sys.argv or '--native-check' in sys.argv:
            mode='--native-check' if '--native-check' in sys.argv else '--preview'
            executable=sys.argv[sys.argv.index(mode)+1]
            native=subprocess.Popen([executable,'--menu-check' if mode=='--native-check' else '--tray-preview',folder])
            def wait_native():
                if native.poll() is None:root.after(300,wait_native)
                else:root.destroy()
            root.after(300,wait_native);root.after(75000,lambda:(native.terminate(),root.destroy()))
            root.mainloop()
            assert native.wait(timeout=5)==0
        else:root.destroy()
        desk.closed=True;desk.tray.close()
    assert not errors,errors
print('Tray IPC, independent on/off, hide without disconnect and dashboard restore passed')
