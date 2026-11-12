"""Test a clean first launch with no Homebrew in PATH and no real VPN changes."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def smoke(bundle,preview=False):
    bundle=pathlib.Path(bundle).resolve();contents=bundle/'Contents'
    with tempfile.TemporaryDirectory(prefix='mochi-clean-') as folder:
        env=dict(os.environ,HOME=folder,PATH='/usr/bin:/bin:/usr/sbin:/sbin',MOCHI_DATA_DIR=folder+'/settings',
                 PYTHONHOME=str(contents/'Frameworks/Python.framework/Versions/3.14'),PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1',
                 TCL_LIBRARY=str(contents/'Resources/Runtime/tcl'),TK_LIBRARY=str(contents/'Resources/Runtime/tk'),
                 SSL_CERT_FILE=str(contents/'Resources/Runtime/cacert.pem'))
        for key in tuple(env):
            if key.startswith('DYLD_') or key in ('PYTHONPATH','PYTHONSTARTUP','__PYVENV_LAUNCHER__'):env.pop(key,None)
        code=r'''
import ctypes,json,pathlib,ssl,sys,tkinter as tk
from unittest.mock import patch
bundle=pathlib.Path(sys.argv[1]);contents=bundle/'Contents'
sys.path.insert(0,str(contents/'Resources/Mochi'))
import app,_tkinter
from runtime_paths import engine_paths,bundle_contents
assert bundle_contents()==contents
assert pathlib.Path(sys.executable).resolve()==(contents/'MacOS/MochiRuntime').resolve()
assert pathlib.Path(_tkinter.__file__).resolve().is_relative_to(bundle)
assert all(pathlib.Path(path).is_relative_to(bundle) for name in ('openvpn','sing-box') for path in engine_paths(name))
assert len(ssl.create_default_context().get_ca_certs())>50
cf=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
cf.CFBundleGetMainBundle.restype=ctypes.c_void_p
cf.CFStringCreateWithCString.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_uint32];cf.CFStringCreateWithCString.restype=ctypes.c_void_p
cf.CFBundleGetValueForInfoDictionaryKey.argtypes=[ctypes.c_void_p,ctypes.c_void_p];cf.CFBundleGetValueForInfoDictionaryKey.restype=ctypes.c_void_p
cf.CFStringGetCString.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_long,ctypes.c_uint32];cf.CFStringGetCString.restype=ctypes.c_bool
cf.CFRelease.argtypes=[ctypes.c_void_p]
key=cf.CFStringCreateWithCString(None,b'CFBundleName',0x08000100)
value=cf.CFBundleGetValueForInfoDictionaryKey(cf.CFBundleGetMainBundle(),key)
buffer=ctypes.create_string_buffer(512)
assert value and cf.CFStringGetCString(value,buffer,len(buffer),0x08000100)
cf.CFRelease(key)
assert buffer.value==b'Mochi'
root=tk.Tk();errors=[]
root.report_callback_exception=lambda kind,error,trace:errors.append(str(error))
with patch.object(app.App,'request'):
    desk=app.App(root,'/unused-clean-launch.sock');root.update()
    assert len(desk.cards)==1
    fields=desk.cards[0]['fields']
    assert all(not fields[name].get() for name in ('path','username','domains','cidrs','dns','server_label'))
    assert desk.cards[0]['connect'].winfo_ismapped()
    root.title('Mochi — clean first launch preview')
    desk.notice.configure(text='Clean first launch preview. No personal profiles loaded. No VPN connections changed.')
    print(json.dumps(dict(display_name=buffer.value.decode(),python=sys.version.split()[0],tk=root.tk.call('info','patchlevel'),
                          blank_profiles=True,system_python_used=False,external_brew_engines_used=False)),flush=True)
    if sys.argv[2]=='preview':
        root.protocol('WM_DELETE_WINDOW',root.destroy);root.after(45000,root.destroy);root.lift();root.focus_force();root.mainloop()
    else:desk.closed=True;root.destroy()
assert not errors,errors
'''
        result=subprocess.run([str(contents/'MacOS/MochiRuntime'),'-B','-s','-S','-c',code,str(bundle),'preview' if preview else 'check'],env=env,timeout=65,check=True,capture_output=not preview,text=True)
        if not preview:print(result.stdout.strip())
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(bundle)],check=True)


if __name__=='__main__':smoke(sys.argv[1],'--preview' in sys.argv)
