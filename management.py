"""Root-only OpenVPN Unix management bridge. Never logs credentials/events."""
import base64, re, socket, threading, time, uuid
from auth import value

def quote(text):
    if not isinstance(text,str) or any(c in text for c in '\r\n\x00'): raise ValueError('Invalid management value')
    return '"'+text.replace('\\','\\\\').replace('"','\\"')+'"'

def dynamic_challenge(line):
    match=re.search(r"\['(CRV1:.*)'\]",line)
    if not match: raise ValueError('Malformed dynamic challenge')
    _,flags,state,username,text=match.group(1).split(':',4)
    value(state,'Challenge state')
    username=base64.b64decode(username,validate=True).decode('utf-8')
    value(username,'Challenge username')
    return dict(flags=flags,state=state,username=username,text=text[:1000])

def dynamic_password(challenge,response):
    return 'CRV1::'+challenge['state']+'::'+value(response,'Challenge response')

def static_password(password,response):
    b64=lambda text:base64.b64encode(text.encode()).decode()
    return 'SCRV1:'+b64(password)+':'+b64(value(response,'Challenge response'))

class Bridge:
    def __init__(self,path,session,lock,initial,key_password=''):
        self.path,self.s,self.lock,self.initial=path,session,lock,initial
        self.key_password=key_password
        self.sock=None; self.pending=None; self.waiting=None; self.used_initial=False; self.closed=False; self.prompts=0
    def start(self): threading.Thread(target=self.run,daemon=True).start()
    def send(self,username,password):
        self.sock.sendall(('username "Auth" '+quote(username)+'\npassword "Auth" '+quote(password)+'\n').encode())
    def prompt(self,kind,text):
        self.prompts+=1
        if self.prompts>5: raise ValueError('Too many authentication challenges; reconnect')
        self.waiting=dict(id=uuid.uuid4().hex,kind=kind,text=text[:1000],created=time.time())
        self.s['challenge']=dict(self.waiting)
    def respond(self,challenge_id,response):
        if not self.waiting or self.waiting['id']!=challenge_id: raise ValueError('This authentication request has expired')
        if time.time()-self.waiting['created']>180: raise ValueError('Authentication request timed out; reconnect')
        if self.waiting['kind']=='private-key':
            self.sock.sendall(('password "Private Key" '+quote(value(response,'Private key password'))+'\n').encode())
        elif self.waiting['kind']=='login-token':
            self.send(self.initial[0],value(response,'Login token')); self.initial=None; self.used_initial=True
        elif self.waiting['kind']=='dynamic':
            self.send(self.pending['username'],dynamic_password(self.pending,response)); self.pending=None
        elif self.waiting['kind']=='static':
            self.send(self.initial[0],static_password(self.initial[1],response)); self.initial=None; self.used_initial=True
        else: raise ValueError('Unsupported authentication request')
        self.waiting=None; self.s['challenge']=None
    def event(self,line):
        if line.startswith('>STATE:'):
            fields=line[7:].split(',')
            if len(fields)>=4 and fields[1] in ('ASSIGN_IP','CONNECTED'):
                import ipaddress
                try:self.s['local_ip']=str(ipaddress.IPv4Address(fields[3]))
                except ValueError:pass
            if len(fields)>=5 and fields[1]=='CONNECTED' and fields[2]=='SUCCESS':
                self.s['vpn_ready']=True
                try:self.s['remote_ip']=str(ipaddress.IPv4Address(fields[4]))
                except ValueError:pass
        if line.startswith('>STATE:') and ',RECONNECTING,' in line and self.s.get('state')=='connected':
            raise ValueError('Tunnel restarted; reconnect manually')
        if line.startswith('>PASSWORD:Verification Failed:'):
            if line.startswith(">PASSWORD:Verification Failed: 'Private Key'"):
                raise ValueError('The private key password was rejected. Reconnect and enter the key password, not the one-time token.')
            if 'CRV1:' in line: self.pending=dynamic_challenge(line)
            else: raise ValueError('VPN rejected the login details or one-time code')
        elif line.startswith(">PASSWORD:Need 'Auth'"):
            if self.pending:
                self.prompt('dynamic',self.pending['text'])
            elif ' SC:' in line:
                if not self.initial: raise ValueError('Fresh login required for server reauthentication')
                match=re.search(r' SC:([01]),(.*)',line)
                if not match: raise ValueError('Unsupported static challenge format')
                self.prompt('static',match.group(2))
            elif not self.used_initial and self.initial:
                if self.initial[1]=='': self.prompt('login-token','Enter the fresh 2FA code from your phone or authenticator.')
                else: self.send(*self.initial); self.initial=None; self.used_initial=True
            else: raise ValueError('Server requests new login details; reconnect manually')
        elif line == ">PASSWORD:Need 'Private Key' password":
            if self.key_password:
                self.sock.sendall(('password "Private Key" '+quote(self.key_password)+'\n').encode())
                self.key_password=''
            else: self.prompt('private-key','Enter the password that unlocks the private key in your VPN file.')
        elif line.startswith('>PASSWORD:Need '):
            raise ValueError('Encrypted private-key prompts are not supported by this build')
    def run(self):
        try:
            deadline=time.monotonic()+15
            while not self.closed:
                sock=socket.socket(socket.AF_UNIX); sock.settimeout(5)
                try: sock.connect(str(self.path)); self.sock=sock; break
                except OSError:
                    sock.close()
                    if time.monotonic()>deadline: raise RuntimeError('Could not connect to private OpenVPN management socket')
                    time.sleep(.1)
            if self.closed: return
            self.sock.settimeout(None)
            self.sock.sendall(b'state on\nhold release\n')
            stream=self.sock.makefile('rb')
            try:
                while not self.closed:
                    raw=stream.readline(16385)
                    if not raw:
                        if not self.closed: raise RuntimeError('OpenVPN management connection closed; inspect session logs')
                        return
                    if len(raw)>16384: raise ValueError('Management event is too large')
                    with self.lock: self.event(raw.decode('utf-8',errors='replace').strip())
            finally: stream.close()
        except Exception as e:
            if not self.closed:
                with self.lock: self.s['auth_error']=str(e)
        finally:
            self.initial=None; self.key_password=''
            if self.sock: self.sock.close()
    def close(self):
        self.closed=True; self.initial=None; self.key_password=''; self.pending=None; self.waiting=None
        self.s['challenge']=None
        if self.sock:
            try: self.sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            self.sock.close()
