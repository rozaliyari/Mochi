"""Desktop inputs and a dashboard that follows macOS appearance."""
import subprocess
import tkinter as tk
from tkinter import ttk


class Entry(ttk.Entry):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        for sequence in ('<Command-v>','<Command-V>','<Control-v>','<<Paste>>'):
            self.bind(sequence,self.paste)
        for sequence in ('<Command-a>','<Command-A>','<Control-a>'):
            self.bind(sequence,self.select_all)
        self.bind('<Button-2>',self.context)
        self.bind('<Button-3>',self.context)
        self.bind('<Control-Button-1>',self.context)

    def paste(self,event=None):
        if self.instate(('disabled',)) or self.instate(('readonly',)):return 'break'
        try:
            value=self.clipboard_get()
            if self.selection_present():
                position=self.index('sel.first');self.delete('sel.first','sel.last');self.icursor(position)
            self.insert('insert',value)
            self.focus_set()
        except tk.TclError:self.bell()
        return 'break'

    def select_all(self,event=None):
        self.selection_range(0,'end');self.icursor('end');return 'break'

    def context(self,event):
        menu=tk.Menu(self,tearoff=False)
        if not self.cget('show'):
            menu.add_command(label='Copy',command=lambda:self.event_generate('<<Copy>>'))
            menu.add_command(label='Cut',command=lambda:self.event_generate('<<Cut>>'))
        menu.add_command(label='Paste',command=self.paste,
                         state='disabled' if self.instate(('disabled',)) or self.instate(('readonly',)) else 'normal')
        menu.add_separator();menu.add_command(label='Select all',command=self.select_all)
        try:menu.tk_popup(event.x_root,event.y_root)
        finally:menu.grab_release()
        return 'break'


def read_appearance():
    return subprocess.run(['/usr/bin/defaults','read','-g','AppleInterfaceStyle'],capture_output=True,text=True).stdout.strip()


def install_theme(root):
    style=ttk.Style(root);style.theme_use('clam')
    appearance=read_appearance()
    dark=appearance=='Dark'
    background,surface,ink,muted,accent=('#171923','#242735','#f2f3f8','#acb3c5','#9388ff') if dark else ('#f3f5fa','#ffffff','#17223b','#66738b','#6454db')
    border='#44495b' if dark else '#d8dfeb'
    button='#33394b' if dark else '#e9edf6'
    root.theme_colors={'background':background,'surface':surface,'ink':ink,'muted':muted,'dark':dark}
    root.configure(bg=background)
    style.configure('.',font=('Helvetica Neue',12),background=background,foreground=ink)
    style.configure('TFrame',background=background)
    style.configure('Surface.TFrame',background=surface)
    style.configure('Surface.TLabel',background=surface)
    style.configure('Title.TLabel',font=('Helvetica Neue',25,'bold'),foreground=ink)
    style.configure('Heading.TLabel',font=('Helvetica Neue',18,'bold'),background=surface)
    style.configure('Muted.TLabel',foreground=muted)
    style.configure('SurfaceMuted.TLabel',foreground=muted,background=surface)
    style.configure('TButton',padding=(13,9),background=button,borderwidth=0)
    style.map('TButton',background=[('active','#4a5064' if dark else '#dce3f1')],foreground=[('disabled','#777f91' if dark else '#9ba4b6')])
    style.configure('Primary.TButton',background=accent,foreground='white',font=('Helvetica Neue',12,'bold'))
    style.map('Primary.TButton',background=[('disabled','#55566c' if dark else '#c4c6dc'),('active','#7968de' if dark else '#5142c3')],foreground=[('disabled','#d8d8e0' if dark else '#f7f7fc')])
    style.configure('TEntry',padding=(10,9),fieldbackground=surface,bordercolor=border,lightcolor=border,darkcolor=border)
    style.map('TEntry',fieldbackground=[('disabled','#2c3040' if dark else '#f0f2f7')],foreground=[('disabled','#8b95a8')],bordercolor=[('focus',accent)])
    style.configure('Card.TLabelframe',padding=20,background=surface,bordercolor=border,borderwidth=1)
    style.configure('Card.TLabelframe.Label',background=surface,font=('Helvetica Neue',11,'bold'),foreground=muted)
    style.configure('TCheckbutton',background=surface,padding=4)
    style.map('TCheckbutton',background=[('active',surface)])
    style.configure('Desk.TNotebook',background=background,borderwidth=0)
    style.layout('Desk.TNotebook.Tab',[])
    style.configure('Connections.Treeview',rowheight=52,fieldbackground=surface,background=surface,borderwidth=0,font=('Helvetica Neue',12))
    style.map('Connections.Treeview',background=[('selected','#49416f' if dark else '#eae6ff')],foreground=[('selected','#ffffff' if dark else '#4436a0')])
    style.configure('Treeview',rowheight=32,fieldbackground=surface,background=surface)
    style.map('Treeview',background=[('selected','#49416f' if dark else '#eae6ff')],foreground=[('selected','#ffffff' if dark else '#4436a0')])
    menu=tk.Menu(root)
    edit=tk.Menu(menu,tearoff=False)
    def invoke(event):
        target=root.focus_get()
        if target:target.event_generate(event)
    edit.add_command(label='Paste',accelerator='⌘V',command=lambda:invoke('<<Paste>>'))
    edit.add_command(label='Copy',accelerator='⌘C',command=lambda:invoke('<<Copy>>'))
    edit.add_command(label='Cut',accelerator='⌘X',command=lambda:invoke('<<Cut>>'))
    menu.add_cascade(label='Edit',menu=edit);root.configure(menu=menu)


def destination_rules(value,include_subdomains=True):
    """Return domain rules and IPv4 host routes from pasted destinations."""
    import re
    import ipaddress
    from urllib.parse import urlsplit
    from dns_rules import domain_rule
    rules=[]
    for item in re.split(r'[,\s]+',value.strip()):
        if not item:continue
        wildcard=item.startswith('*.')
        parsed=urlsplit(item if '://' in item else '//'+item.removeprefix('*.'))
        if parsed.username or parsed.password or parsed.scheme not in ('','http','https'):
            raise ValueError('Enter a website domain or an HTTP/HTTPS URL without login details.')
        name=(parsed.hostname or '').lower().rstrip('.')
        try:address=ipaddress.ip_address(name)
        except ValueError:pass
        else:
            if address.version!=4:raise ValueError('Only IPv4 destinations are supported.')
            from core import network
            rule=str(address)+'/32'
            network(rule)
            if rule not in rules:rules.append(rule)
            continue
        rule=('*.' if include_subdomains or wildcard else '')+name
        domain_rule(rule)
        if rule not in rules:rules.append(rule)
    if not rules:raise ValueError('Enter a website first, for example example.com')
    return rules


def normalize_cidr_destinations(value):
    """Accept CIDRs and pasted URLs in the advanced destination field."""
    import re
    from core import network
    cidrs=[];domains=[]
    for item in (part.strip() for part in value.split(',')):
        if not item:continue
        if re.fullmatch(r'[0-9.]+/[0-9]+',item):
            rule=str(network(item))
            if rule not in cidrs:cidrs.append(rule)
            continue
        candidate=item[1:] if re.match(r'^/[0-9]{1,3}\.',item) else item
        for rule in destination_rules(candidate):
            target=cidrs if rule.endswith('/32') else domains
            if rule not in target:target.append(rule)
    return cidrs,domains
