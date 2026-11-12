"""Native Tk subscription selection, sorting, import and secure cache smoke test."""
import json
import pathlib
import sys
import tempfile
import tkinter as tk
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from subscription_ui import SubscriptionWindow,private_json
from subscriptions import link

root=tk.Tk();root.withdraw()
errors=[]
root.report_callback_exception=lambda *args:errors.append(args)
with tempfile.TemporaryDirectory() as folder:
    rows=[link('vless://00000000-0000-4000-8000-000000000001@8.8.8.8:443?security=tls&sni=example.com#Server-'+str(i)) for i in range(190)]
    for i,row in enumerate(rows):row['tcp']=str(190-i)
    private_json(pathlib.Path(folder)/'subscription-cache.json',rows)
    selected=[]
    window=SubscriptionWindow(root,folder,lambda row:selected.append(row) or True)
    root.update()
    assert len(window.table.get_children())==1
    window.sort('tcp');assert window.table.get_children('g-0')[0]=='189'
    window.table.selection_set('189');window.use()
    assert selected[0]['name']=='Server-189'
    assert window.closed
    window=SubscriptionWindow(root,folder,lambda row:True)
    window.events.put(('latency',('189','https',123)))
    window.events.put(('done',None));window.drain();root.update()
    assert window.table.set('189','https')=='123'
    assert json.loads((pathlib.Path(folder)/'subscription-cache.json').read_text())[189]['https']=='123'
    window.append_group('Second group',[rows[0],rows[1]])
    assert len(window.table.get_children())==2
    window.table.selection_set('g-1')
    with patch('subscription_ui.simpledialog.askstring',return_value='https://example.com/path, 203.0.113.10'):
        window.set_destinations()
    assert window.rows[190]['rules']==dict(cidrs=['203.0.113.10/32'],domains=['*.example.com'])
    window.table.selection_set('g-1')
    with patch('subscription_ui.messagebox.askyesno',return_value=True):window.remove_selected()
    assert len(window.rows)==190
    assert len(json.loads((pathlib.Path(folder)/'subscription-cache.json').read_text()))==190
    window.close();root.update()
root.destroy()
assert not errors,errors
print('Native subscription UI: 190 rows, numeric latency sorting, server selection and private cache passed')
