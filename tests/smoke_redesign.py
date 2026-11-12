"""Verify paste, VLESS setup and visible controls without changing real VPNs."""
import pathlib
import sys
import tempfile
import tkinter as tk
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app
from profiles import DEFAULTS
from subscriptions import link

root=tk.Tk();errors=[]
root.report_callback_exception=lambda kind,error,trace:errors.append(error)
try:previous_clipboard=root.clipboard_get()
except tk.TclError:previous_clipboard=None
with tempfile.TemporaryDirectory() as folder,patch.object(app,'PREFS',pathlib.Path(folder)/'profiles.json'),patch.object(app,'load',return_value=[dict(x) for x in DEFAULTS]),patch.object(app.App,'request'):
    desk=app.App(root,'/unused-preview.sock')
    openvpn=desk.cards[0]
    root.update()
    assert openvpn['setup'].winfo_ismapped()
    openvpn['fields']['path'].set('/tmp/example.ovpn')
    desk.refresh_profile_controls();root.update()
    assert not openvpn['setup'].winfo_ismapped()
    openvpn['fields']['path'].set('')
    desk.refresh_profile_controls();root.update()
    assert openvpn['setup'].winfo_ismapped()
    row=link('vless://00000000-0000-4000-8000-000000000001@8.8.8.8:443?security=tls&sni=example.com#Personal%20server')
    assert desk.use_subscription(row)
    root.update()
    selected=desk.cards[-1]
    assert str(selected['widget'])==desk.notebook.select()
    assert selected['fields']['engine'].get()=='singbox'
    assert desk.connection_list.selection()==('c1',)
    assert selected['connect'].winfo_ismapped() and selected['disconnect'].winfo_ismapped()
    selected['website'].set('https://example.com/account')
    desk.add_website(selected['fields'],selected['website'])
    assert selected['fields']['domains'].get()=='*.example.com'
    assert not selected['website'].get()
    selected['website'].set('http://203.0.113.10/luna/')
    desk.add_website(selected['fields'],selected['website'])
    assert selected['fields']['cidrs'].get()=='203.0.113.10/32'
    assert '203.0.113.10/32' in selected['ip_destinations'].get()
    # A partial selection is replaced at the selection position, not appended.
    entry=selected['website_entry'];entry.insert(0,'before OLD after');entry.selection_range(7,10)
    root.clipboard_clear();root.clipboard_append('NEW');entry.event_generate('<<Paste>>')
    assert entry.get()=='before NEW after'
    entry.selection_range(0,'end');entry.focus_force();root.update()
    root.clipboard_clear();root.clipboard_append('shortcut paste')
    entry.event_generate('<Command-v>');root.update()
    assert entry.get()=='shortcut paste'
    entry.delete(0,'end')
    def login_input():
        dialog=next(w for w in root.winfo_children() if isinstance(w,app.LoginDialog))
        for key,value in [('username','test-user'),('password',' test password with spaces ')]:
            root.clipboard_clear();root.clipboard_append(value)
            dialog.widgets[key].insert(0,'replace this');dialog.widgets[key].selection_range(0,'end')
            dialog.paste_buttons[key].invoke()
            assert dialog.widgets[key].get()==value
        dialog.ok()
    root.after(80,login_input)
    dialog=app.LoginDialog(root,title='Input verification',mode='password')
    assert dialog.result['password']==' test password with spaces '
    dialog.result=None
    def two_step_input():
        dialog=next(w for w in root.winfo_children() if isinstance(w,app.LoginDialog))
        assert dialog.password.get()=='dummy-old-password'
        assert dialog.widgets['password'].winfo_ismapped()
        assert dialog.qr_button.instate(('disabled',))
        dialog.ok()
    root.after(80,two_step_input)
    dialog=app.LoginDialog(root,title='Dummy two-step login',username='alice',mode='dynamic',password='dummy-old-password')
    assert dialog.result['password']=='dummy-old-password' and dialog.result['mode']=='dynamic'
    dialog.result=None
    states={selected['fields']['name'].get():dict(state='connected',interface='utun999',log='',dns_error='',error='')}
    desk.render(states)
    old=entry.get();entry.paste();assert entry.get()==old
    assert selected['connect'].instate(('disabled',))
    assert selected['disconnect'].instate(('!disabled',))
    desk.render({})
    root.clipboard_clear()
    if previous_clipboard is not None:root.clipboard_append(previous_clipboard)
    if '--preview' in sys.argv:
        root.title('Mochi design preview — no real connections changed')
        desk.notice.config(text='Design preview only. Real VPN connections are unchanged.')
        root.protocol('WM_DELETE_WINDOW',root.destroy);root.after(90000,root.destroy);root.deiconify();root.lift();root.focus_force();root.mainloop()
    else:
        desk.closed=True
        root.update();root.destroy()
assert not errors,errors
print('Redesigned UI: login paste, selection replacement, VLESS focus, website setup and on/off states passed')
