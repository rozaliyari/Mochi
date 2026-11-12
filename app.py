#!/usr/bin/env python3
"""Unprivileged configurable desktop dashboard."""
import json, os, pathlib, queue, re, socket, subprocess, sys, threading, tkinter as tk
from tkinter import ttk, filedialog, messagebox
from core import sanitize, policy, suggested_routes, override_server
from auth import credentials, totp, totp_secret, totp_qr, phone_code, value
from profiles import load, save, new_profile, PreferencesError
from settings import MIN_PROFILES, MAX_PROFILES, VERSION
from dialogs import ModalDialog
from ui_widgets import Entry,install_theme,read_appearance,destination_rules,normalize_cidr_destinations
import keychain as saved_credentials

PREFS = pathlib.Path(os.environ.get('MOCHI_DATA_DIR',str(pathlib.Path.home()/'Library/Application Support/Mochi')))/'profiles.json'

def rpc(path,data):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(120); s.connect(path); s.sendall((json.dumps(data)+'\n').encode())
        response = s.makefile('rb').readline(2_100_000)
        if not response.endswith(b'\n'): raise RuntimeError('Incomplete helper response')
        result = json.loads(response)
        if 'error' in result: raise RuntimeError(result['error'])
        return result['result']


class LoginDialog(ModalDialog):
    def __init__(self,parent,title=None,username='',mode='dynamic',password='',seed='',encrypted_key=False,key_password=''):
        self.default_username=username;self.default_mode=mode;self.default_password=password;self.default_seed=seed
        self.encrypted_key=encrypted_key;self.default_key_password=key_password
        super().__init__(parent,title)
    def body(self,master):
        self.mode=tk.StringVar(value=self.default_mode if self.default_mode in ('password','dynamic') else 'password'); self.username=tk.StringVar(value=self.default_username); self.password=tk.StringVar(value=self.default_password); self.default_password=''; self.key_password=tk.StringVar(value=self.default_key_password);self.default_key_password='';self.seed=tk.StringVar(value=self.default_seed);self.default_seed=''
        ttk.Label(master,text='VPN login').grid(row=0,column=0,columnspan=3,sticky='w',pady=8)
        ttk.Radiobutton(master,text='Password',variable=self.mode,value='password',command=self.update_mode).grid(row=1,column=0,columnspan=2,sticky='w')
        ttk.Radiobutton(master,text='Two-step (2FA)',variable=self.mode,value='dynamic',command=self.update_mode).grid(row=2,column=0,columnspan=2,sticky='w')
        self.widgets={}
        self.labels={}
        self.paste_buttons={}
        self.advanced=tk.BooleanVar(value=bool(self.seed.get()))
        inputs=[(3,'username','Username',self.username),(4,'password','Login password (if required)',self.password)]
        if self.encrypted_key:inputs.append((5,'key_password','Private key password',self.key_password))
        inputs.append((6,'seed','Authenticator setup seed',self.seed))
        for row,key,label,var in inputs:
            self.labels[key]=ttk.Label(master,text=label)
            self.labels[key].grid(row=row,column=0,sticky='w',padx=6,pady=8)
            entry=Entry(master,textvariable=var,show='' if key=='username' else '•',width=34)
            entry.grid(row=row,column=1,sticky='ew',padx=6); self.widgets[key]=entry
            paste=ttk.Button(master,text='Paste',command=entry.paste);paste.grid(row=row,column=2,padx=4);self.paste_buttons[key]=paste
        ttk.Checkbutton(master,text='Generate 2FA codes in Mochi',variable=self.advanced,command=self.update_mode).grid(row=7,column=0,columnspan=2,sticky='w')
        self.qr_button=ttk.Button(master,text='Scan QR image…',command=self.scan_qr)
        self.qr_button.grid(row=7,column=2,padx=4)
        self.qr_button.state(['disabled'])
        self.form_error=ttk.Label(master,text='',wraplength=470)
        self.form_error.grid(row=8,column=0,columnspan=3,sticky='w',pady=(8,0))
        self.update_mode(); return self.widgets['username']
    def update_mode(self):
        dynamic=self.mode.get()=='dynamic'
        enabled=dynamic and self.advanced.get()
        for widget in (self.widgets['seed'],self.labels['seed'],self.paste_buttons['seed'],self.qr_button):
            if enabled: widget.grid()
            else: widget.grid_remove()
        if not enabled:self.seed.set('')
    def scan_qr(self):
        image=filedialog.askopenfilename(parent=self,title='Choose Authenticator QR image',filetypes=[('Images','*.png *.jpg *.jpeg *.heic'),('All files','*')])
        if not image:return
        reader=pathlib.Path(__file__).resolve().parents[2]/'Helpers'/'qr-reader'
        try:
            if not reader.is_file():raise ValueError('QR scanner is unavailable in this build')
            result=subprocess.run([str(reader),image],capture_output=True,text=True,timeout=10,check=True)
            self.seed.set(totp_qr(result.stdout.strip()))
        except (OSError,ValueError,subprocess.SubprocessError):
            messagebox.showerror('QR scan','Cannot read a supported 6-digit Authenticator QR from that image.',parent=self)
    def validate(self):
        field='username'
        self.form_error.config(text='')
        for widget in self.widgets.values():widget.state(['!invalid'])
        try:
            value(self.username.get(),'Username')
            if self.mode.get()=='password' or self.password.get():
                field='password';value(self.password.get(),'Login password')
            if self.encrypted_key:
                field='key_password'
                # Clipboard selections often include a terminating newline.
                # Preserve spaces and every character inside the password.
                key=self.key_password.get().strip('\r\n')
                if not key:raise ValueError('Enter the Private key password in its own field.')
                if '\r' in key or '\n' in key:raise ValueError('Private key password must be one line. Paste only the password value.')
                value(key,'Private key password');self.key_password.set(key)
            if self.mode.get()=='dynamic' and self.advanced.get():
                field='seed'
                if not self.seed.get():raise ValueError('Enter an Authenticator setup seed, or turn off code generation to use your phone.')
                totp_secret(self.seed.get())
            return True
        except ValueError as e:
            self.form_error.config(text=str(e));self.initial_focus=self.widgets[field]
            self.initial_focus.state(['invalid']);return False
    def apply(self):
        self.result=dict(username=self.username.get(),password=self.password.get(),mode=self.mode.get(),seed=self.seed.get() if self.mode.get()=='dynamic' else '')
        if self.encrypted_key:self.result['key_password']=self.key_password.get()

class CodeDialog(ModalDialog):
    def __init__(self,parent,title,prompt,seed='',kind='dynamic',expires=None):
        self.kind=kind;self.expires=expires;self.expired=False
        self.prompt,self.seed,self.timer=prompt,('' if kind=='private-key' else seed),None
        super().__init__(parent,title)
    def body(self,master):
        self.code=tk.StringVar(); self.use_generated=tk.BooleanVar(value=bool(self.seed))
        ttk.Label(master,text=self.prompt,wraplength=430).pack(anchor='w',pady=10)
        entry=Entry(master,textvariable=self.code,show='•' if self.kind=='private-key' else '',width=28,font=('',18));entry.pack(fill='x',pady=8)
        self.code_entry=entry
        ttk.Button(master,text='Paste code',command=self.paste_code).pack(anchor='w',pady=4)
        entry.bind('<Command-v>',self.paste_code)
        entry.bind('<Command-V>',self.paste_code)
        if self.seed: ttk.Checkbutton(master,text='Generate from my Authenticator key',variable=self.use_generated).pack(anchor='w')
        self.remaining=ttk.Label(master,text='');self.remaining.pack(anchor='w',pady=6)
        self.update_code(); return entry
    def paste_code(self,event=None):
        try:
            text=self.clipboard_get()
            if self.kind!='private-key':text=phone_code(text)
            from auth import value
            value(text,'Code')
            self.use_generated.set(False)
            self.code.set(text)
            self.code_entry.focus_set()
        except (tk.TclError,ValueError):
            messagebox.showinfo('Paste code','Copy the code first, then click Paste code.',parent=self)
        return 'break'
    def update_code(self):
        import time
        if self.expires is not None and time.time()>=self.expires and self.winfo_viewable():
            self.expired=True;self.cancel();return
        if self.seed and self.use_generated.get():
            self.code.set(totp(self.seed));self.remaining.configure(text=f'New code in {30-int(time.time())%30}s · check your Mac clock')
        else:self.remaining.configure(text='')
        if self.expires is not None:
            seconds=max(0,int(self.expires-time.time()))
            self.remaining.configure(text=self.remaining.cget('text')+f' · Login window expires in {seconds}s')
        self.timer=self.after(500,self.update_code)
    def ok(self,event=None):
        import time
        if self.expires is not None and time.time()>=self.expires:
            self.expired=True;self.cancel();return
        super().ok(event)
    def validate(self):
        from auth import value
        try: value(self.code.get(),'Private key password' if self.kind=='private-key' else 'One-time code');return True
        except ValueError as e: messagebox.showerror('Code required',str(e),parent=self);return False
    def apply(self): self.result=self.code.get() if self.kind=='private-key' else phone_code(self.code.get())
    def destroy(self):
        if self.timer: self.after_cancel(self.timer);self.timer=None
        self.seed=''
        super().destroy()

class ServerDialog(ModalDialog):
    def body(self,master):
        self.values={}
        for key,label,default in [('host','Server IP / hostname',''),('port','Port','1194'),('proto','Protocol','udp'),('ca','CA certificate (.pem / .crt)',''),('cert','Client certificate (if required)',''),('key','Client private key (if required)','')]:
            row=ttk.Frame(master);row.pack(fill='x',pady=5)
            ttk.Label(row,text=label,width=30).pack(side='left')
            self.values[key]=tk.StringVar(value=default)
            if key=='proto':ttk.Combobox(row,textvariable=self.values[key],values=('udp','tcp-client'),state='readonly',width=28).pack(side='left')
            else:Entry(row,textvariable=self.values[key],width=30).pack(side='left')
            if key in ('ca','cert','key'):
                ttk.Button(row,text='Choose…',command=lambda k=key:self.pick(k)).pack(side='left',padx=5)
    def pick(self,key):
        path=filedialog.askopenfilename(parent=self)
        if path:self.values[key].set(path)
    def validate(self):
        from server_profile import build_profile
        try:
            data={k:v.get() for k,v in self.values.items()}
            for k in ('ca','cert','key'):
                path=data[k]
                if path:
                    with open(path) as f:data[k]=f.read(2_000_001)
                if len(data[k])>2_000_000:raise ValueError('Certificate/key file too large')
            self.profile=build_profile(**data)
            return True
        except Exception as e:messagebox.showerror('Server settings',str(e),parent=self);return False
    def apply(self):self.result=self.profile;self.profile=''
    def destroy(self):
        self.profile=''
        super().destroy()


class App:
    def __init__(self,root,path):
        self.root,self.path=root,path
        self.events=queue.Queue(); self.busy=False; self.prompting=False; self.closed=False; self.states={}; self.cards=[]; self.seeds={}; self.seen_challenges=set();self.saved_login_attempts=set();self.code_requested=set()
        root.title(f'Mochi {VERSION} — VPN dashboard');root.geometry('1180x870');root.minsize(1060,780)
        root.protocol('WM_DELETE_WINDOW',self.close);install_theme(root)
        frame=ttk.Frame(root,padding=22);frame.pack(fill='both',expand=True)
        header=ttk.Frame(frame);header.pack(fill='x',pady=(0,18))
        ttk.Label(header,text='Mochi',style='Title.TLabel').pack(side='left')
        ttk.Label(header,text='',style='Muted.TLabel').pack(side='left',padx=20)
        self.summary=ttk.Label(header,text='Checking connections…',style='Muted.TLabel');self.summary.pack(side='right')
        workspace=ttk.Frame(frame);workspace.pack(fill='both',expand=True)
        sidebar=ttk.Frame(workspace,width=245);sidebar.pack(side='left',fill='y',padx=(0,20));sidebar.pack_propagate(False)
        ttk.Label(sidebar,text='CONNECTIONS',style='Muted.TLabel').pack(anchor='w',pady=(3,10))
        self.connection_list=ttk.Treeview(sidebar,columns=('state',),show='tree',selectmode='browse',style='Connections.Treeview',height=11)
        self.connection_list.column('#0',width=160,minwidth=110);self.connection_list.column('state',width=70,minwidth=50)
        self.connection_list.pack(fill='both',expand=True)
        self.connection_list.bind('<<TreeviewSelect>>',self.select_sidebar)
        self.add_button=ttk.Button(sidebar,text='+ Add connection',command=self.add_profile);self.add_button.pack(fill='x',pady=(12,7))
        ttk.Button(sidebar,text='Import VLESS / VMess',command=self.open_subscription,style='Primary.TButton').pack(fill='x')
        main=ttk.Frame(workspace);main.pack(side='left',fill='both',expand=True)
        self.selector=ttk.Combobox(main,state='readonly')
        self.selector.bind('<<ComboboxSelected>>',self.select_connection)
        body=ttk.Notebook(main,style='Desk.TNotebook');body.pack(fill='both',expand=True);self.notebook=body
        body.enable_traversal();body.bind('<<NotebookTabChanged>>',self.selected_connection)
        for p in load(PREFS):self.make_card(p)
        direct=ttk.Frame(body,padding=20,style='Surface.TFrame');body.add(direct,text='DIRECT');self.direct_tab=direct
        ttk.Label(direct,text='Direct connection',style='Heading.TLabel').pack(anchor='w',pady=(0,12))
        ttk.Label(direct,text='Direct domains',style='Surface.TLabel').pack(anchor='w')
        self.direct_domains=tk.StringVar();Entry(direct,textvariable=self.direct_domains).pack(fill='x',pady=8)
        ttk.Label(direct,text='Direct IPv4 networks — optional',style='Surface.TLabel').pack(anchor='w',pady=(14,0))
        self.direct_cidrs=tk.StringVar();Entry(direct,textvariable=self.direct_cidrs).pack(fill='x',pady=8)
        ttk.Button(direct,text='Apply direct rules',command=self.apply_direct).pack(anchor='w')
        self.direct_path=PREFS.with_name('direct.json')
        try:
            settings=json.loads(self.direct_path.read_text());self.direct_cidrs.set(', '.join(settings.get('cidrs',[])));self.direct_domains.set(', '.join(settings.get('domains',[])))
        except (OSError,ValueError,TypeError):pass
        bar=ttk.Frame(main);bar.pack(fill='x',pady=(12,7))
        ttk.Button(bar,text='Save',command=self.save).pack(side='left')
        ttk.Button(bar,text='Refresh',command=self.poll).pack(side='left',padx=8)
        ttk.Button(bar,text='Diagnostics',command=lambda:self.request({'op':'diagnostics'})).pack(side='right')
        self.notice=ttk.Label(main,text='',wraplength=820,style='Muted.TLabel');self.notice.pack(anchor='w',pady=5)
        ttk.Label(main,text='IPv4 · No kill switch',style='Muted.TLabel').pack(anchor='w',pady=4)
        self.details=tk.Text(main,height=3,wrap='word',font=('Menlo',10),bg=root.theme_colors['surface'],fg=root.theme_colors['ink'],borderwidth=0,padx=10,pady=8)

        self.refresh_profile_controls();self.root.after(100,self.drain);self.root.after(150,self.poll)
        self.tray=None
        if os.environ.get('MOCHI_UI_SOCKET'):
            from tray_control import TrayControl
            self.tray=TrayControl(os.environ['MOCHI_UI_SOCKET'])
            self.root.after(100,self.drain_tray)
    def make_card(self,p):
        page=ttk.Frame(self.notebook)
        canvas=tk.Canvas(page,highlightthickness=0,bg=self.root.theme_colors['background'],width=700)
        scrollbar=ttk.Scrollbar(page,orient='vertical',command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set);scrollbar.pack(side='right',fill='y');canvas.pack(side='left',fill='both',expand=True)
        card=ttk.LabelFrame(canvas,text='Connection',style='Card.TLabelframe')
        window=canvas.create_window((0,0),window=card,anchor='nw')
        card.bind('<Configure>',lambda event:canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<Configure>',lambda event:canvas.itemconfigure(window,width=event.width))
        def scroll(event):
            target=self.root.winfo_containing(event.x_root,event.y_root)
            if target and str(target).startswith(str(page)) and card.winfo_height()>canvas.winfo_height():
                canvas.yview_scroll(-1 if event.delta>0 else 1,'units');return 'break'
        self.root.bind('<MouseWheel>',scroll,add='+')
        if hasattr(self,'direct_tab'):self.notebook.insert(self.direct_tab,page,text=p['name'])
        else:self.notebook.add(page,text=p['name'])
        fields={key:tk.StringVar(value=p.get(key,'')) for key in ('name','path','server_override','cidrs','domains','dns','username','auth_mode','server_label')}
        for key,default in [('credential_id',saved_credentials.profile_id(p['name'],PREFS)),('remember','0'),('engine','openvpn')]:
            fields[key]=tk.StringVar(value=p.get(key) or default)
        card.columnconfigure(0,weight=1)
        heading=ttk.Frame(card,style='Surface.TFrame');heading.grid(row=0,column=0,sticky='ew')
        ttk.Label(heading,text='Name',style='Surface.TLabel').pack(side='left',padx=(0,8))
        name_entry=Entry(heading,textvariable=fields['name'],width=26)
        name_entry.pack(side='left',fill='x',expand=True)
        name_entry.bind('<Return>',lambda event:self.save())
        name_entry.bind('<FocusOut>',lambda event:self.save())
        title=ttk.Label(heading,text='',style='Heading.TLabel')
        engine=ttk.Label(heading,text='',style='SurfaceMuted.TLabel');engine.pack(side='right')
        server=ttk.Label(card,text='',style='SurfaceMuted.TLabel',wraplength=720);server.grid(row=1,column=0,sticky='w',pady=(7,15))
        statusbar=ttk.Frame(card,style='Surface.TFrame');statusbar.grid(row=2,column=0,sticky='ew',pady=(0,20))
        state=ttk.Label(statusbar,text='● Off',style='SurfaceMuted.TLabel');state.pack(side='left')
        disconnect=ttk.Button(statusbar,text='Turn off',command=lambda f=fields:self.disconnect(f));disconnect.pack(side='right',padx=(8,0))
        connect=ttk.Button(statusbar,text='Turn on',style='Primary.TButton',command=lambda f=fields:self.connect(f));connect.pack(side='right')
        if fields['engine'].get()!='singbox':
            ttk.Checkbutton(statusbar,text='Save login in Mac Keychain',variable=fields['remember'],onvalue='1',offvalue='0').pack(side='left',padx=(18,0))
            ttk.Button(statusbar,text='Forget',command=lambda:self.forget_passwords(fields)).pack(side='left',padx=8)
        setup=ttk.Frame(card,style='Surface.TFrame');setup.grid(row=3,column=0,sticky='ew',pady=(0,18))
        ttk.Label(setup,text='OpenVPN setup',style='Surface.TLabel',font=('',14,'bold')).pack(anchor='w')
        setup_buttons=ttk.Frame(setup,style='Surface.TFrame');setup_buttons.pack(anchor='w')
        ttk.Button(setup_buttons,text='Import .ovpn file',style='Primary.TButton',command=lambda:self.import_file(fields)).pack(side='left')
        ttk.Button(setup_buttons,text='Set up server manually',command=lambda:self.add_server(fields)).pack(side='left',padx=(8,0))
        ttk.Button(setup_buttons,text='Login settings…',command=lambda:self.configure_login(fields)).pack(side='left',padx=(8,0))
        ttk.Label(card,text='Destinations',style='Surface.TLabel',font=('',14,'bold')).grid(row=4,column=0,sticky='w')
        addrow=ttk.Frame(card,style='Surface.TFrame');addrow.grid(row=6,column=0,sticky='ew');addrow.columnconfigure(0,weight=1)
        website=tk.StringVar();website_entry=Entry(addrow,textvariable=website);website_entry.grid(row=0,column=0,sticky='ew')
        add=ttk.Button(addrow,text='Add',command=lambda:self.add_website(fields,website));add.grid(row=0,column=1,padx=(8,0))
        website_entry.bind('<Return>',lambda event:self.add_website(fields,website))
        ttk.Label(card,text='Domains',style='SurfaceMuted.TLabel').grid(row=7,column=0,sticky='w',pady=(5,2))
        destinations=Entry(card,textvariable=fields['domains']);destinations.grid(row=8,column=0,sticky='ew')
        ip_destinations=tk.StringVar()
        def show_ips(*_):
            addresses=[item.strip() for item in fields['cidrs'].get().split(',') if item.strip()]
            ip_destinations.set('IP routes: '+', '.join(addresses) if addresses else '')
        fields['cidrs'].trace_add('write',show_ips);show_ips()
        ttk.Label(card,textvariable=ip_destinations,style='SurfaceMuted.TLabel',wraplength=700).grid(row=9,column=0,sticky='w',pady=(5,0))
        advanced=ttk.Frame(card,style='Surface.TFrame');advanced.grid(row=11,column=0,sticky='ew');advanced.columnconfigure(1,weight=1)
        expanded=tk.BooleanVar(value=not p.get('path'))
        def toggle():
            if expanded.get():advanced.grid()
            else:advanced.grid_remove()
        ttk.Checkbutton(card,text='Advanced',variable=expanded,command=toggle).grid(row=10,column=0,sticky='w',pady=(0,6))
        edits=[name_entry,website_entry,destinations,add]
        for index,(key,label) in enumerate([('path','Profile file'),('server_override','OpenVPN server override'),('cidrs','Destination CIDRs'),('dns','VPN DNS IPv4')]):
            ttk.Label(advanced,text=label,style='Surface.TLabel').grid(row=index,column=0,sticky='w',padx=(0,10),pady=4)
            entry=Entry(advanced,textvariable=fields[key]);entry.grid(row=index,column=1,sticky='ew',pady=4);edits.append(entry)
        imports=ttk.Frame(advanced,style='Surface.TFrame');imports.grid(row=5,column=1,sticky='w',pady=6)
        choose=ttk.Button(imports,text='Choose .ovpn…',command=lambda:self.import_file(fields))
        manual=ttk.Button(imports,text='Add server IP…',command=lambda:self.add_server(fields))
        editserver=ttk.Button(imports,text='Choose VLESS server…',command=self.open_subscription)
        if fields['engine'].get()=='singbox':editserver.pack(side='left')
        else:choose.pack(side='left');manual.pack(side='left',padx=5)
        edits.extend([choose,manual])
        fields['name'].trace_add('write',lambda *_:self.refresh_profile_controls())
        buttons=ttk.Frame(card,style='Surface.TFrame');buttons.grid(row=12,column=0,sticky='ew',pady=(14,0))
        remove=ttk.Button(buttons,text='Remove connection',command=lambda:self.remove_profile(fields));remove.pack(side='right')
        ttk.Button(buttons,text='View logs',command=lambda:self.logs(fields)).pack(side='left')
        toggle()
        self.cards.append(dict(widget=page,panel=card,fields=fields,label=state,title=title,engine_label=engine,server=server,setup=setup,connect=connect,disconnect=disconnect,remove=remove,entries=edits,website=website,website_entry=website_entry,ip_destinations=ip_destinations,add_website=add,advanced=advanced,canvas=canvas))

    def add_website(self,fields,website):
        if self.states.get(fields['name'].get(),{}).get('state') in ('connecting','connected'):
            self.notice.config(text='Turn this connection off before editing destinations.');return 'break'
        try:
            rules=destination_rules(website.get())
            domains=[rule for rule in rules if not rule.endswith('/32')]
            cidrs=[rule for rule in rules if rule.endswith('/32')]
            existing_domains=[x.strip() for x in fields['domains'].get().split(',') if x.strip()]
            existing_cidrs=[x.strip() for x in fields['cidrs'].get().split(',') if x.strip()]
            fields['domains'].set(', '.join(dict.fromkeys(existing_domains+domains)))
            fields['cidrs'].set(', '.join(dict.fromkeys(existing_cidrs+cidrs)))
            website.set('');self.save()
            self.notice.config(text='Destination added.')
        except ValueError as e:messagebox.showerror('Destination',str(e),parent=self.root)
        return 'break'

    def select_sidebar(self,event=None):
        selected=self.connection_list.selection()
        if selected:
            index=len(self.cards) if selected[0]=='direct' else int(selected[0][1:])
            if self.notebook.index(self.notebook.select())!=index:self.notebook.select(index)

    def refresh_profile_controls(self):
        wanted={'c'+str(i) for i in range(len(self.cards))}|{'direct'}
        for item in self.connection_list.get_children():
            if item not in wanted:self.connection_list.delete(item)
        for i,c in enumerate(self.cards):
            name=c['fields']['name'].get();self.notebook.tab(c['widget'],text=name)
            c['title'].configure(text='')
            proxy=c['fields']['engine'].get()=='singbox'
            c['engine_label'].configure(text='VLESS / VMess' if proxy else 'OpenVPN')
            c['server'].configure(text=c['fields']['server_label'].get() if proxy else pathlib.Path(c['fields']['path'].get()).name or 'Import an .ovpn file above, or use manual setup.')
            if not proxy and not c['fields']['path'].get().strip():c['setup'].grid()
            else:c['setup'].grid_remove()
            state=self.states.get(name,{}).get('state','disconnected')
            badge={'connected':'● On','connecting':'…','error':'! Error'}.get(state,'Off')
            item='c'+str(i)
            if not self.connection_list.exists(item):self.connection_list.insert('','end',iid=item)
            self.connection_list.item(item,text=name,values=(badge,))
            self.connection_list.move(item,'',i)
        if not self.connection_list.exists('direct'):self.connection_list.insert('','end',iid='direct',text='DIRECT')
        self.connection_list.move('direct','',len(self.cards))
        if not self.cards:self.notebook.select(self.direct_tab)
        self.selector.configure(values=[f"{i+1}. {c['fields']['name'].get()}" for i,c in enumerate(self.cards)]+['DIRECT'])
        self.selected_connection()
        self.add_button.configure(state='normal' if len(self.cards)<MAX_PROFILES else 'disabled')
        for c in self.cards:
            active=self.states.get(c['fields']['name'].get(),{}).get('state') in ('connected','connecting')
            c['remove'].configure(state='normal')
        count=sum(s.get('state')=='connected' for s in self.states.values())
        self.summary.config(text=f'{count} / {len(self.cards)} connected')

    def selected_connection(self,event=None):
        try:
            index=self.notebook.index(self.notebook.select());self.selector.current(index)
            item='direct' if index==len(self.cards) else 'c'+str(index)
            if self.connection_list.exists(item) and self.connection_list.selection()!=(item,):
                self.connection_list.selection_set(item);self.connection_list.see(item)
        except (tk.TclError,IndexError):pass

    def select_connection(self,event=None):
        index=self.selector.current()
        if index>=0:self.notebook.select(index)

    def add_profile(self):
        if self.busy:return
        if len(self.cards)>=MAX_PROFILES:
            self.notice.config(text=f'Maximum {MAX_PROFILES} VPNs');return
        p=new_profile(c['fields']['name'].get() for c in self.cards)
        self.make_card(p);self.notebook.select(self.cards[-1]['widget'])
        self.refresh_profile_controls();self.save()

    def open_subscription(self):
        from subscription_ui import SubscriptionWindow
        if getattr(self,'subscription_window',None) and not self.subscription_window.closed:
            self.subscription_window.window.deiconify();self.subscription_window.window.lift();return
        self.subscription_window=SubscriptionWindow(self.root,PREFS.parent,self.use_subscription)

    def use_subscription(self,row):
        from subscription_ui import private_json
        import subscriptions
        if self.busy:return False
        selected=next((c for c in self.cards if str(c['widget'])==self.notebook.select()),None)
        if selected and selected['fields']['engine'].get()=='singbox':
            fields=selected['fields']
            if self.states.get(fields['name'].get(),{}).get('state') in ('connecting','connected'):
                messagebox.showinfo('Disconnect first','Disconnect this VPN before switching its server.');return False
            path=PREFS.parent/'provider-profiles'/('proxy-'+fields['credential_id'].get()+'.json')
            private_json(path,subscriptions.outbound(row['outbound']))
            fields['path'].set(str(path));fields['server_label'].set(row['name'])
            if row.get('rules'):
                fields['cidrs'].set(', '.join(row['rules'].get('cidrs',[])));fields['domains'].set(', '.join(row['rules'].get('domains',[])))
            self.save();self.root.deiconify();self.root.lift();self.root.after(100,selected['website_entry'].focus_force)
            self.notice.config(text='Server selected. Saved server destinations applied.' if row.get('rules') else 'Server selected. Existing destinations kept. Add websites below, then turn on.')
            return True
        if len(self.cards)>=MAX_PROFILES:
            messagebox.showinfo('Profile limit','Remove an unused profile before adding another server.');return False
        p=new_profile(c['fields']['name'].get() for c in self.cards)
        existing={c['fields']['name'].get() for c in self.cards}
        p['name']=next('vless-'+str(i) for i in range(1,MAX_PROFILES+2) if 'vless-'+str(i) not in existing)
        p['engine']='singbox'
        p['server_label']=row['name']
        if row.get('rules'):
            p['cidrs']=', '.join(row['rules'].get('cidrs',[]));p['domains']=', '.join(row['rules'].get('domains',[]))
        p['credential_id']=saved_credentials.profile_id(p['name'],PREFS)
        path=PREFS.parent/'provider-profiles'/('proxy-'+p['credential_id']+'.json')
        private_json(path,subscriptions.outbound(row['outbound']))
        p['path']=str(path)
        self.make_card(p);self.notebook.select(self.cards[-1]['widget']);self.save()
        self.root.deiconify();self.root.lift();self.root.after(100,self.cards[-1]['website_entry'].focus_force)
        self.notice.config(text='Server added.')
        return True

    def remove_profile(self,fields):
        if self.busy:return
        name=fields['name'].get()
        if not re.fullmatch(r'[A-Za-z0-9 _-]{1,40}',name) or not name.strip():
            messagebox.showerror('Connection name','Use 1–40 letters, numbers, spaces, _ or -.',parent=self.root);return
        if sum(c['fields']['name'].get()==name for c in self.cards)>1:
            messagebox.showerror('Connection name','Connection names must be unique before one can be removed.',parent=self.root);return
        self.pending_remove=fields
        if self.states.get(name,{}).get('state') in ('connected','connecting'):
            self.request({'op':'disconnect','name':name})
        else:self.request({'op':'forget','name':name})

    def finish_remove(self,name):
        fields=getattr(self,'pending_remove',None)
        for c in self.cards:
            if c['fields'] is fields:
                self.notebook.forget(c['widget']);c['widget'].destroy();self.cards.remove(c)
                self.seeds.pop(name,None);break
        self.pending_remove=None
        self.refresh_profile_controls();self.save()

    def forget_passwords(self,fields):
        try:
            saved_credentials.delete(fields['credential_id'].get())
            fields['remember'].set('0');self.save()
            self.notice.config(text='Saved login passwords removed from this Mac Keychain.')
        except saved_credentials.KeychainError as e:messagebox.showerror('Keychain',str(e))

    def apply_direct(self):
        if self.busy:return
        from dns_rules import domain_rule
        from core import network
        try:
            split=lambda s:[x.strip() for x in s.split(',') if x.strip()]
            cidrs=split(self.direct_cidrs.get());domains=split(self.direct_domains.get())
            for c in cidrs:network(c)
            for d in domains:domain_rule(d)
            # Persist only on a successful helper acknowledgement (see drain).
            self.pending_direct=dict(cidrs=cidrs,domains=domains)
            self.request(dict(op='direct-rules',**self.pending_direct))
        except Exception as e:messagebox.showerror('DIRECT rules',str(e))
    def write(self,text):
        self.details.pack(fill='x',pady=(6,0));self.details.delete('1.0','end');self.details.insert('end',text)
    def save(self):
        try:
            rows=[{k:v.get().strip() if k=='name' else v.get() for k,v in c['fields'].items()} for c in self.cards]
            names=[row['name'] for row in rows]
            if any(not name or len(name)>40 for name in names):raise PreferencesError('Connection names must contain 1–40 characters.')
            if len(set(names))!=len(names):raise PreferencesError('Connection names must be unique.')
            save(PREFS,rows);self.refresh_profile_controls();self.notice.config(text='Saved.')
        except (OSError,PreferencesError) as e: messagebox.showerror('Cannot save',str(e)); return False
        return True
    def add_server(self,fields):
        self.prompting=True
        try:dialog=ServerDialog(self.root,title='Add OpenVPN server')
        finally:self.prompting=False
        if dialog.result is None:return
        path=filedialog.asksaveasfilename(parent=self.root,title='Save private OpenVPN profile',defaultextension='.ovpn',filetypes=[('OpenVPN profile','*.ovpn')])
        if path:
            try:
                # Atomic 0600 replace; never follow a preexisting destination symlink.
                import os,tempfile
                fd,tmp=tempfile.mkstemp(dir=pathlib.Path(path).parent)
                try:
                    with os.fdopen(fd,'w') as f:f.write(dialog.result)
                    os.replace(tmp,path)
                finally:
                    if os.path.exists(tmp):os.unlink(tmp)
                fields['path'].set(path);fields['engine'].set('openvpn');self.save()
            except OSError as e:messagebox.showerror('Cannot save profile',str(e))
        dialog.result=None
    def import_file(self,fields):
        p=filedialog.askopenfilename(filetypes=[('OpenVPN profile','*.ovpn')])
        if p:
            try:
                with open(p) as f: content=f.read(2_000_001)
                sanitize(content)
                routes=suggested_routes(content) if not fields['cidrs'].get().strip() else []
                if routes: fields['cidrs'].set(', '.join(routes))
                fields['path'].set(p);fields['engine'].set('openvpn'); self.save()
                if routes:self.notice.config(text=f'Imported {len(routes)} destination routes from the VPN file. Review them before connecting.')
                self.configure_login(fields)
            except Exception as e: messagebox.showerror('Profile not supported',str(e))
    def configure_login(self,fields):
        try:
            path=fields['path'].get()
            if not path:raise ValueError('Import an .ovpn file first.')
            with open(path) as f:profile=sanitize(f.read(2_000_001))
            profile=override_server(profile,fields['server_override'].get())
            encrypted_key='ENCRYPTED' in profile
            has_login='auth-user-pass' in profile.splitlines()
            if not has_login and not encrypted_key:
                self.notice.config(text='This VPN file does not request a username, password or access key.');return
            stored=saved_credentials.load(fields['credential_id'].get()) if fields['remember'].get()=='1' else None
            binding=saved_credentials.binding(profile)
            if stored and stored.get('binding')!=binding:stored=None
            self.prompting=True
            try:
                if has_login:
                    dialog=LoginDialog(self.root,title='Save VPN login — '+fields['name'].get(),username=fields['username'].get() or (stored or {}).get('username',''),mode=fields['auth_mode'].get(),password=(stored or {}).get('password',''),seed=(stored or {}).get('otp_seed',''),encrypted_key=encrypted_key,key_password=(stored or {}).get('key_password',''))
                    if dialog.result is None:return
                    login=dialog.result
                else:
                    dialog=CodeDialog(self.root,title='Save VPN access key — '+fields['name'].get(),prompt='VPN access key',kind='private-key')
                    if dialog.result is None:return
                    login=dict(username='',password='',mode='password',seed='',key_password=dialog.result)
            finally:self.prompting=False
            saved_credentials.save(fields['credential_id'].get(),dict(username=login['username'],password=login['password'],key_password=login.get('key_password',''),otp_seed=login['seed'],mode=login['mode'],binding=binding))
            fields['username'].set(login['username']);fields['auth_mode'].set(login['mode']);fields['remember'].set('1')
            self.seeds[fields['name'].get()]=login['seed']
            self.save();dialog.result=None
            self.notice.config(text='Login saved in Mac Keychain. Add destinations, then turn on.')
        except Exception as e:messagebox.showerror('Login settings',str(e),parent=self.root)
    def connect(self,fields):
        if self.busy: self.notice.config(text='A request is in progress. Please try Connect again in a moment.'); return
        try:
            card=next((c for c in self.cards if c['fields'] is fields),None)
            if card and card['website'].get().strip():
                self.add_website(fields,card['website'])
                if card['website'].get().strip():return
            p={k:v.get().strip() for k,v in fields.items()}
            if not p['path']: raise ValueError('Choose your .ovpn file first.')
            names=[c['fields']['name'].get() for c in self.cards]
            if names.count(p['name'])>1:raise ValueError('Each project needs a unique name.')
            split=lambda s:[x.strip() for x in s.split(',') if x.strip()]
            if p.get('engine')=='singbox':
                import subscriptions
                subscriptions.binary()
                with open(p['path']) as f:outbound=subscriptions.outbound(json.loads(f.read(2_000_001)))
                cidrs,extra_domains=normalize_cidr_destinations(p['cidrs'])
                domains=list(dict.fromkeys(split(p['domains'])+extra_domains));policy(cidrs,domains,p['dns'])
                fields['cidrs'].set(', '.join(cidrs));fields['domains'].set(', '.join(domains))
                if not self.save():return
                self.request(dict(op='connect',engine='singbox',name=p['name'],outbound=outbound,cidrs=cidrs,domains=domains,dns=p['dns']))
                return
            with open(p['path']) as f: profile=sanitize(f.read(2_000_001))
            profile=override_server(profile,p.get('server_override',''))
            cidrs,extra_domains=normalize_cidr_destinations(p['cidrs'])
            domains=list(dict.fromkeys(split(p['domains'])+extra_domains));policy(cidrs,domains,p['dns'])
            fields['cidrs'].set(', '.join(cidrs));fields['domains'].set(', '.join(domains))
            names=[c['fields']['name'].get() for c in self.cards]
            if names.count(p['name'])>1: raise ValueError('Each project needs a unique name.')
            if not self.save(): return
            stored=saved_credentials.load(p['credential_id']) if fields['remember'].get()=='1' else None
            profile_binding=saved_credentials.binding(profile)
            if stored and (stored.get('binding')!=profile_binding or p['username'] and stored['username']!=p['username']):
                stored=None
                self.notice.config(text='VPN settings changed; enter the login again to update saved passwords.')
            request=dict(op='connect',name=p['name'],profile=profile,cidrs=cidrs,domains=domains,dns=p['dns'])
            self.code_requested.discard(p['name'])
            encrypted_key='ENCRYPTED' in profile
            has_login='auth-user-pass' in profile.splitlines()
            reuse=False
            if has_login:
                reuse=(stored and stored.get('mode')==p.get('auth_mode') and stored.get('username')
                       and (stored.get('mode')=='dynamic' or stored.get('password'))
                       and (not encrypted_key or stored.get('key_password')))
                if reuse:
                    login=dict(username=stored['username'],password=stored['password'],mode=stored['mode'])
                    self.seeds[p['name']]=stored.get('otp_seed','')
                    self.saved_login_attempts.add(p['name'])
                    if encrypted_key:request['key_password']=stored['key_password']
                else:
                    self.prompting=True
                    try: dialog=LoginDialog(self.root,title='VPN login — '+p['name'],username=p.get('username','') or (stored or {}).get('username',''),mode=p.get('auth_mode','password'),password=(stored or {}).get('password',''),seed=(stored or {}).get('otp_seed',''),encrypted_key=encrypted_key,key_password=(stored or {}).get('key_password',''))
                    finally: self.prompting=False
                    if dialog.result is None: return
                    login=dialog.result
                    self.seeds[p['name']]=login.pop('seed','')
                    if encrypted_key:request['key_password']=login.pop('key_password')
                    fields['username'].set(login['username']);fields['auth_mode'].set(login['mode']);self.save()
                    dialog.result=None
                request['credentials']=login
            if encrypted_key and 'key_password' not in request:
                request['key_password']=(stored or {}).get('key_password','')
                if not request['key_password']:
                    self.prompting=True
                    try:
                        key_dialog=CodeDialog(self.root,title='Private key password — '+p['name'],prompt='Enter your VPN access / private-key password. This unlocks the VPN file; it is not a login password or 2FA code.',kind='private-key')
                    finally:self.prompting=False
                    if key_dialog.result is None:return
                    request['key_password']=key_dialog.result;key_dialog.result=None
            if fields['remember'].get()=='1' and not (stored and (reuse or not has_login)):
                login=request.get('credentials',{})
                saved_credentials.save(p['credential_id'],dict(username=login.get('username',p.get('username','')),password=login.get('password',''),key_password=request.get('key_password',''),otp_seed=self.seeds.get(p['name'],'') if login.get('mode')=='dynamic' else '',mode=login.get('mode','password'),binding=profile_binding))
                self.saved_login_attempts.add(p['name'])
            self.request(request)
        except Exception as e: messagebox.showerror('Cannot connect',str(e))
    def disconnect(self,fields): self.request(dict(op='disconnect',name=fields['name'].get()))
    def logs(self,fields):
        name=fields['name'].get(); s=self.states.get(name,{})
        self.write(name+'\n'+s.get('error','')+'\n'+s.get('log','No session logs yet.'))
    def request(self,data):
        if self.busy or self.closed: return
        self.busy=True
        self.request_op=data['op']
        def worker():
            try:
                if data.get('engine')=='singbox':
                    info=rpc(self.path,{'op':'info'})
                    version=tuple(int(x) for x in info.get('version','0.0').split('.')[:2])
                    if info.get('protocol',0)<2 or version<(0,8):
                        raise RuntimeError('Restart Mochi to load the updated VPN service before connecting VLESS / VMess.')
                self.events.put((data['op'],rpc(self.path,data),None))
            except Exception as e: self.events.put((data['op'],None,str(e)))
        threading.Thread(target=worker,daemon=True).start()
    def drain(self):
        if self.closed: return
        try:
            while True:
                op,result,error=self.events.get_nowait(); self.busy=False
                if error:
                    if op in ('disconnect','forget'):self.pending_remove=None
                    self.notice.config(text=error)
                    if op=='status': self.summary.config(text='Local service unavailable')
                    else: messagebox.showerror('Mochi',error)
                elif op=='forget':self.finish_remove(result['name'])
                elif op=='disconnect' and getattr(self,'pending_remove',None):
                    self.request({'op':'forget','name':self.pending_remove['name'].get()})
                elif op=='diagnostics':self.write(json.dumps(result,indent=2,ensure_ascii=False))
                elif op=='status': self.render(result)
                elif op=='direct-rules':
                    save(self.direct_path,self.pending_direct)
                    self.notice.config(text='DIRECT rules applied. Saved rules must be applied again after restarting.')
                else: self.notice.config(text='Request completed. Updating connection status…'); self.poll()
        except queue.Empty: pass
        self.root.after(100,self.drain)
    def render(self,states):
        self.states=states; count=sum(s['state']=='connected' for s in states.values())
        self.summary.config(text=f'{count} / {len(self.cards)} connected')
        for name in list(self.seeds):
            if states.get(name,{}).get('state') in ('disconnected','error'): self.seeds.pop(name,None)
        for c in self.cards:
            s=states.get(c['fields']['name'].get(),{}); state=s.get('state','disconnected'); active=state in ('connecting','connected')
            name=c['fields']['name'].get()
            if name in self.saved_login_attempts and state in ('connected','error'):
                self.saved_login_attempts.discard(name)
                if state=='error' and name not in self.code_requested:
                    self.notice.config(text='Saved login failed. Use Forget to enter new login details.')
            text={'connected':'● On','connecting':'Connecting…','disconnected':'● Off','error':'Connection error'}.get(state,state)
            c['label'].config(text=text+(' · '+s['interface'] if s.get('interface') else ''),foreground='#16834a' if state=='connected' else '#b45309' if state=='error' else '#64748b')
            c['connect'].configure(state='disabled' if active else 'normal'); c['disconnect'].configure(state='normal' if active else 'disabled')
            for e in c['entries']: e.configure(state='disabled' if active else 'normal')
            if s.get('dns_error'): self.notice.config(text='DNS: '+s['dns_error'])
            if s.get('error'): self.notice.config(text=c['fields']['name'].get()+': '+s['error'])
        self.refresh_profile_controls()
        for name,s in states.items():
            challenge=s.get('challenge')
            if challenge and challenge['id'] not in self.seen_challenges:
                self.seen_challenges.add(challenge['id']); self.prompting=True
                if challenge['kind']!='private-key':self.code_requested.add(name)
                seed=self.seeds.get(name,'')
                if seed and challenge['kind'] in ('dynamic','static','login-token'):
                    self.prompting=False
                    self.request({'op':'auth-response','name':name,'challenge_id':challenge['id'],'response':totp(seed)})
                    break
                self.show_dashboard()
                try: dialog=CodeDialog(self.root,title=('Private key password — ' if challenge['kind']=='private-key' else '2FA code — ')+name,prompt=challenge['text'],seed=self.seeds.get(name,''),kind=challenge['kind'],expires=challenge['created']+180)
                finally: self.prompting=False
                if dialog.result is None:
                    self.request({'op':'disconnect','name':name})
                    if dialog.expired:self.write('The login window expired. Click Connect and use a fresh phone code.')
                else: self.request({'op':'auth-response','name':name,'challenge_id':challenge['id'],'response':dialog.result});dialog.result=None
                break
    def poll(self):
        if not self.prompting: self.request({'op':'status'})
    def tick(self):
        if not self.closed:
            if self.root.theme_colors['dark'] != (read_appearance()=='Dark'):
                install_theme(self.root)
                for card in self.cards:card['canvas'].configure(bg=self.root.theme_colors['background'])
                self.details.configure(bg=self.root.theme_colors['surface'],fg=self.root.theme_colors['ink'])
            self.poll(); self.root.after(3000,self.tick)
    def show_dashboard(self):
        self.root.deiconify();self.root.lift();self.root.focus_force()
    def drain_tray(self):
        if self.closed or not self.tray:return
        try:
            while True:self.tray_command(self.tray.commands.get_nowait())
        except queue.Empty:pass
        rows=[dict(id=c['fields']['credential_id'].get(),name=c['fields']['name'].get()[:80],state=self.states.get(c['fields']['name'].get(),{}).get('state','disconnected')) for c in self.cards]
        self.tray.publish(rows,(self.busy and getattr(self,'request_op','')!='status') or self.prompting)
        self.root.after(150,self.drain_tray)
    def tray_command(self,command):
        if command['op']=='show':self.show_dashboard();return
        card=next((c for c in self.cards if c['fields']['credential_id'].get()==command.get('id')),None)
        if not card:return
        self.notebook.select(card['widget'])
        if self.busy or self.prompting:
            self.show_dashboard();self.notice.config(text='Finish the current request or login before changing a connection.');return
        state=self.states.get(card['fields']['name'].get(),{}).get('state','disconnected')
        if command['op']=='connect' and state not in ('connected','connecting'):
            if not card['fields']['path'].get() or not any(card['fields'][key].get().strip() for key in ('domains','cidrs','dns')) and not card['website'].get().strip():
                self.show_dashboard();card['website_entry'].focus_set()
                self.notice.config(text='Import a profile and add its websites here before turning on this connection.');return
            if card['fields']['engine'].get()!='singbox':self.show_dashboard()
            self.connect(card['fields'])
        elif command['op']=='disconnect' and state in ('connected','connecting'):
            self.disconnect(card['fields'])
    def close(self):
        if self.closed:return
        if getattr(self,'tray',None):
            self.save();self.root.withdraw()
            if getattr(self,'subscription_window',None) and not self.subscription_window.closed:self.subscription_window.window.withdraw()
            return
        if not messagebox.askokcancel('Close Mochi','Disconnect all tunnels and close the dashboard?'): return
        if self.busy:
            messagebox.showinfo('Please wait','Wait for the current request to finish, then close again.');return
        self.closed=True; self.seeds.clear(); self.save()
        if getattr(self,'subscription_window',None) and not self.subscription_window.closed:self.subscription_window.close()
        self.root.destroy()

def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if len(args)!=1:return 2
    root=tk.Tk()
    try:
        dashboard=App(root,args[0]);root.after(3000,dashboard.tick);root.mainloop()
        return 0
    except PreferencesError as e:
        root.withdraw();messagebox.showerror('Local settings need attention',str(e),parent=root)
        root.destroy();return 1
    finally:
        if 'dashboard' in locals() and getattr(dashboard,'tray',None):dashboard.tray.close()
        try:rpc(args[0],{'op':'shutdown'})
        except Exception as e:print('Could not stop helper. Check its Terminal window:',e,file=sys.stderr)


if __name__=='__main__':sys.exit(main())
