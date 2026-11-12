"""Modal dialogs using public Tk APIs, compatible with macOS Tk 8 and Tk 9."""
import tkinter as tk
from tkinter import ttk

class ModalDialog(tk.Toplevel):
    def __init__(self,parent,title=None):
        super().__init__(parent)
        self.parent=parent
        self.result=None
        self.withdraw()
        try:
            if title:self.title(title)
            if parent.winfo_viewable():self.transient(parent)
            self.resizable(False,False)
            body=ttk.Frame(self,padding=14)
            self.initial_focus=self.body(body) or self
            body.pack(fill='both',expand=True)
            buttons=ttk.Frame(self,padding=(14,0,14,14))
            ttk.Button(buttons,text='Cancel',command=self.cancel).pack(side='right',padx=(6,0))
            ttk.Button(buttons,text='OK',command=self.ok).pack(side='right')
            buttons.pack(fill='x')
            self.bind('<Return>',self.ok)
            self.bind('<Escape>',self.cancel)
            self.protocol('WM_DELETE_WINDOW',self.cancel)
            self.update_idletasks()
            width,height=self.winfo_reqwidth(),self.winfo_reqheight()
            if parent.winfo_viewable():
                x=parent.winfo_rootx()+(parent.winfo_width()-width)//2
                y=parent.winfo_rooty()+(parent.winfo_height()-height)//2
            else:
                x=(self.winfo_screenwidth()-width)//2
                y=(self.winfo_screenheight()-height)//2
            self.geometry(f'+{max(0,x)}+{max(0,y)}')
            self.deiconify()
            self.wait_visibility()
            self.grab_set()
            self.lift()
            self.initial_focus.focus_force()
            self.wait_window(self)
        except Exception:
            if self.winfo_exists():self.destroy()
            raise
    def body(self,master):return None
    def validate(self):return True
    def apply(self):pass
    def ok(self,event=None):
        if not self.validate():
            self.initial_focus.focus_set()
            return
        try:self.apply()
        finally:self.cancel()
    def cancel(self,event=None):
        self.grab_release()
        if self.parent.winfo_exists():self.parent.focus_set()
        self.destroy()
