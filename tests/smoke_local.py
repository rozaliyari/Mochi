"""Optional macOS UI + local fake-server smoke test. No VPN or route changes."""
import pathlib,socket,sys,tempfile,threading,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from management import Bridge

def bridge_smoke():
    errors=[]; done=threading.Event(); lock=threading.RLock()
    with tempfile.TemporaryDirectory(prefix='td-test-',dir='/tmp') as d:
        path=d+'/m.sock'; server=socket.socket(socket.AF_UNIX);server.bind(path);server.listen(1);server.settimeout(8)
        def fake_server():
            try:
                conn,_=server.accept();conn.settimeout(8)
                with conn,conn.makefile('rb') as stream:
                    assert stream.readline()==b'state on\n';assert stream.readline()==b'hold release\n'
                    conn.sendall(b">PASSWORD:Need 'Private Key' password\n")
                    assert stream.readline()==b'password "Private Key" "dummy-key-pass"\n'
                    conn.sendall(b">PASSWORD:Need 'Auth' username/password\n")
                    assert stream.readline()==b'username "Auth" "alice"\n'
                    assert stream.readline()==b'password "Auth" "test-only"\n'
                    conn.sendall(b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:state:YWxpY2U=:Enter OTP']\n>PASSWORD:Need 'Auth' username/password\n")
                    assert stream.readline()==b'username "Auth" "alice"\n'
                    assert stream.readline()==b'password "Auth" "CRV1::state::123456"\n'
                    done.set()
            except Exception as e: errors.append(e);done.set()
        thread=threading.Thread(target=fake_server);thread.start()
        state={'state':'connecting','challenge':None};bridge=Bridge(path,state,lock,('alice','test-only'));bridge.start()
        try:
            deadline=time.monotonic()+8
            while not state.get('challenge') and time.monotonic()<deadline:time.sleep(.02)
            assert state.get('challenge'),state
            with lock:bridge.respond(state['challenge']['id'],'dummy-key-pass')
            while not state.get('challenge') and time.monotonic()<deadline:time.sleep(.02)
            assert state.get('challenge'),state
            with lock:bridge.respond(state['challenge']['id'],'123456')
            assert done.wait(8)
            if errors:raise errors[0]
        finally:bridge.close();server.close();thread.join(timeout=8)
    print('Local Unix management two-step exchange passed')

def ui_smoke():
    import tkinter as tk
    from unittest.mock import patch
    import app,keychain
    from profiles import DEFAULTS
    root=tk.Tk();root.withdraw();errors=[]
    def callback_error(kind,error,traceback):
        errors.append(error)
        for window in root.winfo_children():
            if isinstance(window,app.ModalDialog):window.cancel()
    root.report_callback_exception=callback_error
    print('UI runtime:',sys.executable,'Tk',root.tk.call('info','patchlevel'))
    def schedule(cls,fill):
        def run():
            dialog=next(w for w in root.winfo_children() if isinstance(w,cls))
            fill(dialog)
        root.after(60,run)
    with tempfile.TemporaryDirectory() as tmp,patch.object(app,'PREFS',pathlib.Path(tmp)/'profiles.json'),patch.object(app,'load',return_value=[dict(x) for x in DEFAULTS]),patch.object(app.App,'request'),patch.object(app.saved_credentials,'load',return_value=None),patch.object(app,'save'):
        dashboard=app.App(root,'/unused-test.sock');assert len(dashboard.cards)==1
        for _ in range(9):dashboard.add_profile()
        assert len(dashboard.cards)==10
        dashboard.add_profile();assert len(dashboard.cards)==10
        for index in (0,4,9,10):
            dashboard.selector.current(index);dashboard.select_connection()
            assert dashboard.notebook.index(dashboard.notebook.select())==index
        while len(dashboard.cards)>1:
            fields=dashboard.cards[-1]['fields'];dashboard.pending_remove=fields
            dashboard.finish_remove(fields['name'].get())
        dashboard.remove_profile(dashboard.cards[0]['fields']);assert len(dashboard.cards)==1
        def fixed_input(dialog):
            dialog.mode.set('password');dialog.username.set('alice');dialog.password.set('test-only');dialog.ok()
        schedule(app.LoginDialog,fixed_input)
        fixed=app.LoginDialog(root,title='Test fixed password')
        assert fixed.result['password']=='test-only';fixed.result=None
        schedule(app.LoginDialog,lambda d:d.cancel())
        assert app.LoginDialog(root,title='Cancel test').result is None
        def key_validation(dialog):
            dialog.username.set('alice')
            assert not dialog.validate()
            assert dialog.initial_focus is dialog.widgets['key_password']
            dialog.key_password.set(' dummy-key \r\n')
            assert dialog.validate() and dialog.key_password.get()==' dummy-key '
            dialog.key_password.set('dummy\nkey')
            assert not dialog.validate()
            dialog.key_password.set('dummy-key')
            dialog.advanced.set(True);dialog.update_mode()
            assert not dialog.validate()
            assert dialog.initial_focus is dialog.widgets['seed']
            dialog.advanced.set(False);dialog.update_mode();dialog.ok()
        schedule(app.LoginDialog,key_validation)
        checked_key=app.LoginDialog(root,title='Test field validation',mode='dynamic',encrypted_key=True)
        assert checked_key.result['key_password']=='dummy-key'
        checked_key.result=None
        def totp_input(dialog):
            dialog.username.set('alice');dialog.mode.set('dynamic');dialog.advanced.set(True);dialog.update_mode()
            dialog.seed.set('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');dialog.ok()
        schedule(app.LoginDialog,totp_input)
        login=app.LoginDialog(root,title='Test Authenticator')
        schedule(app.CodeDialog,lambda d:d.ok())
        code=app.CodeDialog(root,title='Test phone code',prompt='Test only',seed=login.result['seed'])
        assert len(code.result)==6 and code.seed==''
        def paste_key(dialog):
            dialog.clipboard_clear();dialog.clipboard_append('dummy-key-pass');dialog.paste_code()
            assert dialog.code.get()=='dummy-key-pass';dialog.clipboard_clear();dialog.ok()
        schedule(app.CodeDialog,paste_key)
        key=app.CodeDialog(root,title='Test private-key paste',prompt='Test only',kind='private-key')
        assert key.result=='dummy-key-pass';key.result=None
        from tests_base import PROFILE
        profile=pathlib.Path(tmp)/'dummy.ovpn'
        profile.write_text(PROFILE+'<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\ndummy\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n')
        fields=dashboard.cards[0]['fields'];fields['path'].set(str(profile));fields['domains'].set('*.example.com');fields['auth_mode'].set('dynamic')
        fields['domains'].set('')
        def save_before_connect(dialog):
            dialog.username.set('alice');dialog.key_password.set('dummy-key-pass');dialog.ok()
        schedule(app.LoginDialog,save_before_connect)
        with patch.object(dashboard,'save',return_value=True),patch.object(app.saved_credentials,'save') as stored_login:
            dashboard.configure_login(fields)
            assert fields['remember'].get()=='1'
            assert stored_login.call_args.args[1]['key_password']=='dummy-key-pass'
        fields['remember'].set('0');fields['domains'].set('*.example.com')
        def enter_login(dialog):
            dialog.username.set('alice');dialog.key_password.set('dummy-key-pass');dialog.ok()
        schedule(app.LoginDialog,enter_login)
        with patch.object(dashboard,'save',return_value=True),patch.object(dashboard,'request') as send:
            dashboard.connect(fields)
            payload=send.call_args.args[0]
            assert payload['key_password']=='dummy-key-pass'
            assert payload['credentials']==dict(username='alice',password='',mode='dynamic')
        fields['auth_mode'].set('password');fields['remember'].set('1')
        stored=dict(username='alice',password='dummy-saved',key_password='dummy-key-pass',mode='password',binding=keychain.binding(app.sanitize(profile.read_text())))
        with patch.object(dashboard,'save',return_value=True),patch.object(dashboard,'request') as send,patch.object(app.saved_credentials,'load',return_value=stored),patch.object(app.saved_credentials,'save') as store,patch.object(app,'LoginDialog',side_effect=AssertionError('saved fixed login must skip the form')):
            dashboard.connect(fields)
            assert send.call_args.args[0]['key_password']=='dummy-key-pass'
            assert send.call_args.args[0]['credentials']==dict(username='alice',password='dummy-saved',mode='password')
            store.assert_not_called()
        fields['auth_mode'].set('dynamic')
        stored['password']='';stored['mode']='dynamic'
        dashboard.render({fields['name'].get():dict(state='error',error='dummy saved-login failure',log='')})
        with patch.object(dashboard,'save',return_value=True),patch.object(dashboard,'request') as send,patch.object(app.saved_credentials,'load',return_value=stored),patch.object(app.saved_credentials,'save'),patch.object(app,'LoginDialog',side_effect=AssertionError('saved two-step login must skip the form')):
            dashboard.connect(fields)
            assert send.call_args.args[0]['key_password']=='dummy-key-pass'
            assert send.call_args.args[0]['credentials']==dict(username='alice',password='',mode='dynamic')
        expired=app.CodeDialog(root,title='Expired login test',prompt='Test only',expires=time.time()-1)
        assert expired.expired and expired.result is None
        dashboard.closed=True;login.result=None
    root.destroy()
    if errors:raise errors[0]
    print('1–10 VPN add/remove/selection, saved-password login, key paste and login expiry passed')

if __name__=='__main__':bridge_smoke();ui_smoke()
