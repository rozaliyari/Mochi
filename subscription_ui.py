"""Subscription server picker; all network work stays off the Tk thread."""
import concurrent.futures
import json
import os
import pathlib
import queue
import tempfile
import threading
import uuid
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import subscriptions as sub
from ui_widgets import Entry, normalize_cidr_destinations


def private_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream: json.dump(value, stream)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


class SubscriptionWindow:
    def __init__(self, parent, folder, select):
        self.folder, self.select = pathlib.Path(folder), select
        self.rows, self.events, self.busy, self.closed = [], queue.Queue(), False, False
        self.window = tk.Toplevel(parent)
        self.window.title('VLESS / VMess — Subscription servers')
        self.window.geometry('1000x620')
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        box = ttk.Frame(self.window, padding=14); box.pack(fill='both', expand=True)
        ttk.Label(box, text='Subscription URL').pack(anchor='w')
        self.url = tk.StringVar()
        Entry(box, textvariable=self.url, show='•').pack(fill='x', pady=6)
        self.group_name=tk.StringVar(value='My servers')
        ttk.Label(box,text='Import group').pack(anchor='w')
        Entry(box,textvariable=self.group_name).pack(fill='x',pady=4)
        buttons = ttk.Frame(box); buttons.pack(fill='x', pady=6)
        self.controls = []
        for title, callback in [('Load subscription', self.load), ('Import links / JSON…', self.import_file),
                                ('Test TCP — all servers', lambda: self.test(False)),
                                ('Test HTTPS — selected', lambda: self.test(True)),
                                ('Add selected server', self.use)]:
            b = ttk.Button(buttons, text=title, command=callback); b.pack(side='left', padx=(0, 5)); self.controls.append(b)
        actions=ttk.Frame(box);actions.pack(fill='x',pady=4)
        for title,callback in [('Import clipboard',self.import_clipboard),('Set destinations',self.set_destinations),('Remove selected',self.remove_selected)]:
            button=ttk.Button(actions,text=title,command=callback);button.pack(side='left',padx=(0,5));self.controls.append(button)
        self.table = ttk.Treeview(box, columns=('name', 'protocol', 'transport', 'tcp', 'https', 'status'), show='tree headings', selectmode='extended')
        self.table.heading('#0',text='Group');self.table.column('#0',width=160)
        for column, width in [('name', 280), ('protocol', 70), ('transport', 90), ('tcp', 95), ('https', 95), ('status', 210)]:
            self.table.heading(column, text={'tcp':'TCP ms', 'https':'HTTPS ms'}.get(column, column.title()),
                               command=lambda c=column: self.sort(c))
            self.table.column(column, width=width, minwidth=60)
        scrollbar = ttk.Scrollbar(box, orient='vertical', command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y'); self.table.pack(fill='both', expand=True)
        self.note = ttk.Label(box, text='', wraplength=930)
        self.note.pack(anchor='w', pady=10)
        try:
            cached = self.folder/'subscription-cache.json'
            if cached.exists():
                data = json.loads(cached.read_text())
                if not isinstance(data, list) or len(data)>sub.MAX_SERVERS: raise ValueError()
                for row in data:
                    if 'outbound' in row: row['outbound'] = sub.outbound(row['outbound'])
                self.populate(data)
        except (OSError, ValueError, TypeError, KeyError): self.note.config(text='Saved subscription could not be read. Load it again.')
        self.window.after(100, self.drain)

    def close(self):
        self.closed = True; self.url.set(''); self.window.destroy()

    def populate(self, rows):
        self.rows = rows
        self.table.delete(*self.table.get_children())
        groups={}
        for i, row in enumerate(rows):
            group=row.get('group_id','local')
            if group not in groups:
                groups[group]='g-'+str(len(groups))
                self.table.insert('', 'end',iid=groups[group],text=row.get('group_name','Local servers'),open=True)
            o = row.get('outbound', {})
            self.table.insert(groups[group], 'end', iid=str(i), values=(row['name'], o.get('type', '—'), o.get('transport', {}).get('type', 'tcp') if o else '—', row.get('tcp','—'), row.get('https','—'), row.get('error', 'Ready to test')))
        self.note.config(text=f'{len(rows)} servers · {sum("outbound" in r for r in rows)} supported.')

    def work(self, operation):
        if self.busy: return
        self.busy = True
        for control in self.controls: control.configure(state='disabled')
        def run():
            try: operation()
            except Exception: self.events.put(('error', 'Could not complete this operation. Check the subscription and connection.'))
            finally: self.events.put(('done', None))
        threading.Thread(target=run, daemon=True).start()

    def load(self):
        url = self.url.get().strip()
        if not url: return
        name=self.group_name.get().strip()[:80] or 'Subscription'
        self.note.config(text='Downloading subscription…')
        def run():
            try: rows = sub.fetch(url)
            except ValueError as e: self.events.put(('error', str(e))); return
            self.events.put(('append', (name,rows)))
        self.work(run)

    def import_file(self):
        paths = filedialog.askopenfilenames(parent=self.window, title='Import links, Base64 subscriptions or outbound JSON')
        if not paths: return
        def run():
            batches=[]
            for path in paths:
                with open(path) as f: data = f.read(sub.MAX_BYTES+1)
                batches.append((pathlib.Path(path).stem[:80],sub.parse(data)))
            if len(self.rows)+sum(len(rows) for _,rows in batches)>sub.MAX_SERVERS:
                raise ValueError('Server library limit reached')
            for batch in batches:self.events.put(('append',batch))
        self.work(run)

    def append_group(self,name,rows):
        if len(self.rows)+len(rows)>sub.MAX_SERVERS:
            self.note.config(text='Library limit: 500 servers. Remove a group before importing.');return
        group=uuid.uuid4().hex
        combined=self.rows+[dict(row,group_id=group,group_name=name) for row in rows]
        private_json(self.folder/'subscription-cache.json',combined)
        self.populate(combined)

    def import_clipboard(self):
        if self.busy:return
        try:
            data=self.window.clipboard_get()
            rows=sub.parse(data)
            self.append_group(self.group_name.get().strip()[:80] or 'Clipboard',rows)
        except (tk.TclError,ValueError):
            self.note.config(text='Copy VLESS / VMess links, a Base64 subscription or supported JSON first.')

    def selected_ids(self):
        ids=[]
        for item in self.table.selection():
            for child in (self.table.get_children(item) if item.startswith('g-') else (item,)):
                if child not in ids:ids.append(child)
        return ids

    def remove_selected(self):
        if self.busy:return
        ids=set(self.selected_ids())
        if not ids:return
        if not messagebox.askyesno('Remove servers',f'Remove {len(ids)} servers from this library? Existing VPN connections are kept.',parent=self.window):return
        rows=[row for i,row in enumerate(self.rows) if str(i) not in ids]
        private_json(self.folder/'subscription-cache.json',rows);self.populate(rows)

    def set_destinations(self):
        ids=self.selected_ids()
        if self.busy or not ids:return
        previous=self.rows[int(ids[0])].get('rules',{})
        initial=', '.join(previous.get('cidrs',[])+previous.get('domains',[]))
        value=simpledialog.askstring('Destinations','Domains, URLs, IPv4 addresses or CIDRs (comma separated)',initialvalue=initial,parent=self.window)
        if value is None:return
        try:
            cidrs,domains=normalize_cidr_destinations(value)
            if not cidrs and not domains:raise ValueError('Add at least one destination.')
            rows=[dict(row) for row in self.rows]
            for item in ids:rows[int(item)]['rules']=dict(cidrs=cidrs,domains=domains)
            private_json(self.folder/'subscription-cache.json',rows);self.populate(rows)
            self.note.config(text=f'Destinations saved for {len(ids)} servers. Applied when you select a server for a VPN connection.')
        except (ValueError,OSError) as e:messagebox.showerror('Destinations',str(e),parent=self.window)

    def test(self, https):
        ids = self.selected_ids() if https else [str(i) for i in range(len(self.rows))]
        if https and not ids:
            messagebox.showinfo('Select servers', 'Select one or more servers for an HTTPS test.', parent=self.window); return
        ids = [i for i in ids if 'outbound' in self.rows[int(i)]]
        if not ids: return
        try:
            if https: sub.binary()
        except ValueError as e: messagebox.showerror('Connection engine', str(e), parent=self.window); return
        self.note.config(text=f'Testing {len(ids)} servers… Results appear as each test completes. You can sort by latency.')
        def run():
            with concurrent.futures.ThreadPoolExecutor(max_workers=4 if https else 8) as pool:
                jobs = {pool.submit(sub.real_latency if https else sub.tcp_latency, self.rows[int(i)]): i for i in ids}
                for future in concurrent.futures.as_completed(jobs):
                    if self.closed:
                        for pending in jobs: pending.cancel()
                        break
                    self.events.put(('latency', (jobs[future], 'https' if https else 'tcp', future.result())))
        self.work(run)

    def sort(self, column):
        def value(i):
            raw = self.table.set(i, column)
            return (int(raw) if raw.isdecimal() else float('inf')) if column in ('tcp', 'https') else raw.casefold()
        for group in self.table.get_children():
            for n,item in enumerate(sorted(self.table.get_children(group),key=value)):self.table.move(item,group,n)

    def use(self):
        ids = self.selected_ids()
        if len(ids) != 1:
            messagebox.showinfo('Select one server', 'Select exactly one supported server.', parent=self.window); return
        row = self.rows[int(ids[0])]
        if 'outbound' not in row: return
        if self.select(row):self.close()

    def drain(self):
        if self.closed: return
        try:
            while True:
                kind, data = self.events.get_nowait()
                if kind == 'rows': self.populate(data); self.url.set('')
                elif kind == 'append': self.append_group(*data);self.url.set('')
                elif kind == 'latency':
                    index, column, value = data
                    display=str(value) if value is not None else 'Failed'
                    self.rows[int(index)][column]=display
                    self.table.set(index, column, display)
                    self.table.set(index, 'status', ('HTTPS verified' if column=='https' else 'TCP reachable') if value is not None else ('HTTPS failed' if column=='https' else 'TCP failed'))
                elif kind == 'error': self.note.config(text=data)
                elif kind == 'done':
                    self.busy = False
                    if self.rows:
                        try:private_json(self.folder/'subscription-cache.json',self.rows)
                        except OSError:self.note.config(text='Results shown; could not save the local subscription cache.')
                    for control in self.controls: control.configure(state='normal')
        except queue.Empty: pass
        self.window.after(100, self.drain)
