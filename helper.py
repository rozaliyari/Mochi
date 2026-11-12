#!/usr/bin/env python3
"""Run in foreground with sudo. No network listener; local owner-only socket."""
import hashlib, ipaddress, json, os, pathlib, re, signal, socket, socketserver, subprocess, sys, tempfile, threading, time
from core import sanitize, policy, conflicts, network
from auth import credentials, value
from dns_rules import ResolverFiles, DNSService, domain_rule, choose_rule, upstream_query, ipv4_answers, make_query
from management import Bridge
from settings import MAX_PROFILES, VERSION
from runtime_paths import engine_paths

LOCK = threading.RLock()
SESSIONS = {}
STOP = threading.Event()
ROOT = None
DNS = None
SYSTEM_DNS = []
DIRECT = {'cidrs': [], 'domains': []}
BYPASS = []
BASE_ROUTE = {}


def system_network():
    result = run(['/usr/sbin/scutil', '--dns'])
    addresses = list(dict.fromkeys(re.findall(r'nameserver\[\d+\] : (\d+\.\d+\.\d+\.\d+)', result.stdout)))
    addresses = [a for a in addresses if not ipaddress.IPv4Address(a).is_loopback]
    default = run(['/sbin/route', '-n', 'get', 'default']).stdout
    gateway = re.search(r'gateway:\s*(\d+\.\d+\.\d+\.\d+)', default)
    interface = re.search(r'interface:\s*(\w+)', default)
    return addresses, dict(gateway=gateway.group(1) if gateway else '', interface=interface.group(1) if interface else '')


def bypass_route(n):
    if n in BYPASS: return
    if not BASE_ROUTE.get('gateway') or not BASE_ROUTE.get('interface'):
        raise ValueError('Cannot determine the original system gateway for DIRECT rules')
    current = run(['/sbin/route','-n','get','-net',str(n)])
    dest = re.search(r'destination:\s*(\S+)',current.stdout)
    # An existing exact route is never replaced. Broader VPN routes may be
    # overridden by a new, more-specific direct destination.
    if dest and dest.group(1) == str(n.network_address):
        raise ValueError('An existing route already owns DIRECT destination '+str(n))
    result = run(['/sbin/route','-n','add','-net',str(n),BASE_ROUTE['gateway']])
    if result.returncode: raise RuntimeError('Cannot add DIRECT route: '+result.stderr.strip())
    BYPASS.append(n)


def remove_bypass():
    errors=[]
    for n in list(reversed(BYPASS)):
        r=run(['/sbin/route','-n','get','-net',str(n)])
        if (re.search(r'gateway:\s*'+re.escape(BASE_ROUTE.get('gateway',''))+r'\s',r.stdout)
                and re.search(r'interface:\s*'+re.escape(BASE_ROUTE.get('interface',''))+r'\s',r.stdout)):
            result=run(['/sbin/route','-n','delete','-net',str(n),BASE_ROUTE['gateway']])
            if result.returncode:
                errors.append('DIRECT cleanup failed: '+str(n)); continue
        BYPASS.remove(n)
    if errors: raise RuntimeError('; '.join(errors))


def active_domain_rules():
    rules=[(d,'DIRECT') for d in DIRECT['domains']]
    for name,s in SESSIONS.items():
        if not s.get('stopping') and s['state'] in ('connecting','connected') and s.get('dev'):
            rules.extend((d,name) for d in s['domains'])
    return rules


def sync_resolvers():
    global DNS
    domains=[d for d,_ in active_domain_rules()]
    if domains and DNS is None: DNS=DNSService(resolve_domain,journal='/var/run/mochi-dns.json')
    if DNS: DNS.files.install(domains,DNS.port)


def resolve_domain(query,name):
    with LOCK:
        owner=choose_rule(active_domain_rules(),name)
        session=SESSIONS.get(owner)
        upstreams=([session['dns']] if session and session['dns'] else SYSTEM_DNS)
        if session and (session.get('stopping') or session['process'].poll() is not None):
            raise RuntimeError('Selected VPN is unavailable')
    if not upstreams: raise RuntimeError('No DNS resolver available; enter the company DNS IP')
    response=None
    for address in upstreams:
        try: response=upstream_query(query,address); break
        except (ValueError,OSError): continue
    if response is None: raise RuntimeError('Selected DNS server did not respond')
    addresses=ipv4_answers(response,query)
    with LOCK:
        # Recheck after the network wait; a disconnect must not create new routes.
        if owner != choose_rule(active_domain_rules(),name): raise RuntimeError('DNS rule changed')
        if session:
            if session.get('stopping') or session['process'].poll() is not None: raise RuntimeError('VPN stopped')
            for address in addresses:
                n=network(address+'/32')
                if any(n.overlaps(x) for x in DIRECT['cidrs']): raise ValueError('VPN answer conflicts with DIRECT CIDR')
                add_route(session,n)
            session['answers']=sorted(set(session['answers'])|addresses)
        else:
            for address in addresses:
                n=network(address+'/32')
                if any(n.overlaps(r) for s in SESSIONS.values() if not s.get('stopping') for r in s['reserved']+s['owned']):
                    if any(n==r for s in SESSIONS.values() if not s.get('stopping') for r in s['reserved']+s['owned']):
                        raise ValueError('DIRECT DNS answer is also owned by a VPN')
                    bypass_route(n)
    return response


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=15, env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})

def route(action, cidr, dev):
    return run(['/sbin/route','-n',action,'-net',str(cidr),'-interface',dev])

def remove_routes(s):
    for n in list(reversed(s['owned'])):
        # Only delete if the destination still resolves through our interface.
        r = run(['/sbin/route','-n','get','-net',str(n)])
        if re.search(r'interface:\s*'+re.escape(s['dev'])+r'\s', r.stdout):
            result = route('delete', n, s['dev'])
            if result.returncode: raise RuntimeError('Route cleanup failed: '+result.stderr)
        s['owned'].remove(n)

def disconnect(s):
    s['stopping'] = True
    resolver_error=None
    try: sync_resolvers()
    except Exception as e: resolver_error=e
    if s.get('bridge'): s['bridge'].close()
    p = s['process']
    if p.poll() is None:
        p.terminate()
        try: p.wait(10)
        except subprocess.TimeoutExpired: p.kill(); p.wait(5)
    if s.get('engine')=='singbox':
        try:(s['log'].parent/'engine.json').unlink(missing_ok=True)
        except OSError:pass
    remove_routes(s)
    s['state'] = 'disconnected'
    if resolver_error: raise resolver_error

def add_route(s, n):
    if n in s['owned']: return
    if any(ipaddress.IPv4Address(peer) in n for peer in s.get('peers', [])):
        raise ValueError('Destination includes an OpenVPN transport endpoint')
    for direct in DIRECT['cidrs']:
        if n.overlaps(direct) and n.prefixlen >= direct.prefixlen:
            raise ValueError('VPN destination conflicts with an equal or broader DIRECT rule')
    others = [r for x in SESSIONS.values() if x is not s for r in (x['reserved'] if x['process'].poll() is None else [])+x['owned']]
    conflicts([n], others)
    # Never replace an existing route. Reject destinations already covered by a
    # specific route (LAN, another VPN, or administrator policy).
    old = run(['/sbin/route','-n','get','-net',str(n)])
    dest = re.search(r'destination:\s*(\S+)', old.stdout)
    if dest and dest.group(1) not in ('default','0.0.0.0') and not re.search(r'interface:\s*'+re.escape(s['dev'])+r'\s', old.stdout):
        raise ValueError('Existing specific system route covers '+str(n)+'; refusing to replace it')
    r = route('add',n,s['dev'])
    if r.returncode: raise RuntimeError('Cannot add '+str(n)+': '+r.stderr.strip())
    s['owned'].append(n)

def transport_safe_routes(nets, peers):
    """Keep broad destination coverage while leaving transport hosts outside it."""
    hosts=[ipaddress.IPv4Network(str(ipaddress.IPv4Address(peer))+'/32') for peer in set(peers)]
    result=[]
    for net in nets:
        parts=[net]
        for host in hosts:
            if net==host:raise ValueError('Destination is an OpenVPN transport endpoint')
            parts=[piece for part in parts for piece in (part.address_exclude(host) if host.subnet_of(part) else [part])]
        result.extend(parts)
    return list(ipaddress.collapse_addresses(result))


def refresh(s):
    # The local split resolver installs a route for every A answer before it is
    # delivered to the system resolver. Old IP routes stay until disconnect.
    s['refreshed'] = time.time()


def warm_domains(s):
    for rule in s['domains']:
        name,suffix=domain_rule(rule)
        if suffix:continue
        try:resolve_domain(make_query(name),name)
        except (OSError,ValueError,RuntimeError) as e:
            if not s['stopping']:s['dns_warmup_error']=str(e)


def monitor(s):
    while not STOP.wait(1):
        with LOCK:
            if s['stopping']: return
            try:
                if s.get('auth_error'): raise RuntimeError(s['auth_error'])
                if s.get('challenge') and time.time()-s['challenge']['created']>180: raise RuntimeError('Authentication challenge timed out')
                log = s['log'].read_text(errors='replace')[-100000:]
                if s['process'].poll() is not None: raise RuntimeError('VPN engine exited; inspect logs')
                if s.get('engine')=='singbox' and s['state']=='connecting':
                    info=run(['/sbin/ifconfig',s['expected_dev']])
                    if info.returncode==0 and re.search(r'inet\s+'+re.escape(s['local_ip'])+r'\s',info.stdout):
                        s['vpn_ready']=True
                if s['state'] == 'connecting' and (s.get('vpn_ready') or 'Initialization Sequence Completed' in log):
                    match = re.findall(r'(?:Opened utun device|TUN/TAP device)\s+(utun\d+)',log)
                    if not match and s.get('local_ip'):
                        current='';candidates=[]
                        for line in run(['/sbin/ifconfig']).stdout.splitlines():
                            interface=re.match(r'^(utun\d+):',line)
                            if not line.startswith((' ','\t')):current=interface.group(1) if interface else ''
                            if current and re.search(r'inet\s+'+re.escape(s['local_ip'])+r'\s',line):candidates.append(current)
                        if len(candidates)==1:match=candidates
                    if not match: raise RuntimeError('Cannot uniquely identify the macOS utun interface')
                    s['dev'] = match[-1]
                    peers = re.findall(r'\[AF_INET\]([0-9.]+):[0-9]+',log)
                    if s.get('remote_ip') and s['remote_ip'] not in peers:peers.append(s['remote_ip'])
                    s['peers'] = peers
                    for n in transport_safe_routes(s['reserved'],peers): add_route(s,n)
                    if not s['dns'] and s['domains']:
                        pushed=re.findall(r'dhcp-option DNS (\d+\.\d+\.\d+\.\d+)',log)
                        if pushed:
                            candidate=str(ipaddress.IPv4Address(pushed[0]))
                            # Public resolvers do not require a tunnel route. Avoid
                            # reserving the same global DNS IP in every project.
                            # Private company DNS stays bound to its VPN route.
                            if not ipaddress.IPv4Address(candidate).is_global:
                                n=network(candidate+'/32');add_route(s,n);s['dns_via_vpn']=True
                            s['dns']=candidate
                    for address in s.get('cached_answers',[]):add_route(s,network(address+'/32'))
                    s['answers']=list(s.get('cached_answers',[]))
                    refresh(s); s['state'] = 'connected'
                    sync_resolvers()
                    threading.Thread(target=warm_domains,args=(s,),daemon=True).start()
                elif s['state'] == 'connected':
                    # Reconnect events are handled by the management bridge.
                    if time.time()-s['refreshed'] > 60: refresh(s)
                elif time.time()-s['started'] > 300: raise RuntimeError('Connection timed out')
            except Exception as e:
                s['error'] = str(e)
                try: disconnect(s)
                except Exception as cleanup: s['error'] += '; '+str(cleanup)
                s['state'] = 'error'; return

def dispatch(req):
    op = req.get('op')
    if op == 'shutdown':
        threading.Thread(target=server.shutdown, daemon=True).start()
        return {'ok': True}
    if op == 'status':
        return {k:{'state':s['state'],'error':s.get('error',''),'interface':s['dev'],'dns':s.get('dns',''),'dns_mode':'vpn' if s.get('dns_via_vpn') else 'system','dns_error':DNS.last_error if DNS else '','answers':s['answers'],'challenge':s.get('challenge'),'log':s['log'].read_text(errors='replace')[-16000:]} for k,s in SESSIONS.items()}
    if op == 'diagnostics':
        return dict(dns_port=DNS.port if DNS else None,dns_error=DNS.last_error if DNS else '',
                    resolver_domains=sorted(DNS.files.owned) if DNS else [],
                    direct_cidrs=list(map(str,DIRECT['cidrs'])),direct_domains=DIRECT['domains'],
                    system_dns=SYSTEM_DNS,original_gateway=BASE_ROUTE,
                    note='DIRECT uses the original system route. Browser DoH and cached IPs bypass split DNS.')
    if op == 'direct-rules':
        if any(s['process'].poll() is None for s in SESSIONS.values()):
            raise ValueError('Disconnect Mochi VPNs before editing DIRECT rules')
        cidrs=[network(x) for x in req.get('cidrs',[])]
        domains=req.get('domains',[])
        for d in domains: domain_rule(d)
        previous=dict(DIRECT)
        remove_bypass()
        try:
            DIRECT.update(cidrs=cidrs,domains=domains)
            for n in cidrs: bypass_route(n)
            sync_resolvers()
        except Exception:
            remove_bypass();DIRECT.update(previous)
            for n in previous['cidrs']: bypass_route(n)
            sync_resolvers();raise
        return {'ok':True}
    if op=='info':return {'version':VERSION,'max_profiles':MAX_PROFILES,'protocol':2}
    name = req.get('name','')
    if not re.fullmatch(r'[A-Za-z0-9 _-]{1,40}',name) or not name.strip(): raise ValueError('Name: use 1–40 letters, numbers, spaces, _ or -')
    if op=='forget':
        s=SESSIONS.get(name)
        if s:
            if s['process'].poll() is None:raise ValueError('Disconnect this VPN before removing it')
            if s['owned']:raise ValueError('Route cleanup must finish before removing this VPN')
            if not s.get('stopping'):disconnect(s)
            SESSIONS.pop(name)
            sync_resolvers()
        return {'ok':True,'name':name}
    if op == 'auth-response':
        session = SESSIONS[name]
        if not session.get('bridge'): raise ValueError('No authentication session')
        session['bridge'].respond(req.get('challenge_id'),req.get('response'))
        return {'ok':True}
    if op == 'disconnect':
        disconnect(SESSIONS[name]); return {'ok':True}
    if op != 'connect': raise ValueError('Unknown operation')
    if name in SESSIONS and SESSIONS[name]['process'].poll() is None: raise ValueError('Already running')
    if sum(s['process'].poll() is None for s in SESSIONS.values()) >= MAX_PROFILES: raise ValueError(f'Maximum {MAX_PROFILES} tunnels')
    if name in SESSIONS and SESSIONS[name]['owned']: raise ValueError('Cleanup outstanding; restart helper after resolving routes')
    nets, domains = policy(req.get('cidrs',[]),req.get('domains',[]),req.get('dns',''))
    if not nets and not domains: raise ValueError('At least one destination or domain is required')
    conflicts(nets, [n for n in DIRECT['cidrs'] if any(r.overlaps(n) and r.prefixlen>=n.prefixlen for r in nets)])
    new_bases={domain_rule(d) for d in domains}
    pending_rules=[(d,owner) for owner,other in SESSIONS.items() if other['process'].poll() is None for d in other['domains']]
    for d,owner in active_domain_rules()+pending_rules:
        if domain_rule(d) in new_bases and owner != name:
            raise ValueError('The same domain rule already belongs to '+owner)
    conflicts(nets,[r for s in SESSIONS.values() for r in s['reserved']+s['owned'] if s['process'].poll() is None])
    engine=req.get('engine','openvpn')
    if engine not in ('openvpn','singbox'):raise ValueError('Unsupported VPN engine')
    if engine=='singbox':
        return connect_proxy(req,nets,domains)
    config = sanitize(req['profile'])
    identity=hashlib.sha256(json.dumps([config,list(map(str,nets)),domains,req.get('dns','')]).encode()).hexdigest()
    previous=SESSIONS.get(name,{})
    cached_answers=list(previous.get('answers',[])) if previous.get('identity')==identity else []
    needs_auth = 'auth-user-pass' in config.splitlines()
    auth_values = None
    if needs_auth:
        supplied = req.get('credentials', {})
        auth_values = credentials(supplied.get('username'), supplied.get('password'), supplied.get('mode','password'), supplied.get('otp',''), supplied.get('otp_format',''))
    config = '\n'.join(line for line in config.splitlines() if line != 'auth-user-pass')+'\n'
    key_password=req.get('key_password','')
    if key_password: value(key_password,'Private key password')
    directory = pathlib.Path(tempfile.mkdtemp(dir=ROOT))
    cfg, log = directory/'client.ovpn', directory/'openvpn.log'
    cfg.write_text(config); cfg.chmod(0o600); log.touch(mode=0o600)
    args = [BINARY,'--config',str(cfg),'--dev','tun','--route-nopull','--route-noexec','--script-security','1','--pull-filter','ignore','redirect-gateway','--pull-filter','ignore','redirect-private','--pull-filter','ignore','ifconfig-ipv6','--auth-nocache','--verb','3','--log',str(log)]
    management_path = directory/'management.sock'
    args += ['--management',str(management_path),'unix','--management-query-passwords','--management-hold','--auth-retry','interact']
    if needs_auth: args += ['--auth-user-pass']
    # Capture parser failures that occur before OpenVPN processes --log.
    with log.open('ab',buffering=0) as startup_output:
        p = subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=startup_output,stderr=subprocess.STDOUT,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'},cwd=directory)
    s = dict(identity=identity,cached_answers=cached_answers,process=p,log=log,reserved=nets,domains=domains,dns=req.get('dns',''),dns_via_vpn=bool(req.get('dns','')),owned=[],dev='',state='connecting',answers=[],started=time.time(),refreshed=0,stopping=False,challenge=None)
    s['bridge'] = Bridge(management_path,s,LOCK,auth_values,key_password)
    SESSIONS[name] = s
    s['bridge'].start()
    threading.Thread(target=monitor,args=(s,),daemon=True).start()
    return {'ok':True}


def connect_proxy(req,nets,domains):
    import subscriptions
    name=req['name']
    outbound=subscriptions.outbound(req.get('outbound'))
    peers=subscriptions.public_addresses(outbound['server'],outbound['server_port'])
    if any(ipaddress.IPv4Address(peer) in n for peer in peers for n in nets):
        raise ValueError('Destination includes the proxy transport endpoint')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*',BASE_ROUTE.get('interface','')):
        raise ValueError('No safe original network interface; reconnect Wi-Fi and restart Mochi')
    if subscriptions.real_latency({'outbound':outbound}) is None:
        raise ValueError('Selected server failed the HTTPS connection test. Test and choose another subscription server.')
    used=set(re.findall(r'^(utun\d+):',run(['/sbin/ifconfig']).stdout,re.M))
    number=None
    for i in range(200,254):
        if 'utun'+str(i) in used:continue
        existing=run(['/sbin/route','-n','get','-net',f'198.19.{i-199}.0/30'])
        destination=re.search(r'destination:\s*(\S+)',existing.stdout)
        if destination and destination.group(1) not in ('default','0.0.0.0'):continue
        number=i;break
    if number is None:raise ValueError('No free tunnel interface')
    dev='utun'+str(number)
    local_ip=f'198.19.{number-199}.1'
    # Pin the already checked public endpoint; prevent DNS/route recursion.
    outbound['server']=peers[0]
    config=subscriptions.engine_config(outbound,dev,local_ip+'/30',BASE_ROUTE['interface'])
    directory=pathlib.Path(tempfile.mkdtemp(dir=ROOT))
    cfg,log=directory/'engine.json',directory/'engine.log'
    fd=os.open(cfg,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(config,f)
    log.touch(mode=0o600)
    binary=subscriptions.binary()
    result=run([binary,'check','-c',str(cfg)])
    if result.returncode:
        cfg.unlink(missing_ok=True)
        raise ValueError('Connection engine rejected this configuration; unsupported settings')
    try:
        with log.open('ab',buffering=0) as output:
            process=subprocess.Popen([binary,'run','-c',str(cfg)],stdin=subprocess.DEVNULL,stdout=output,stderr=subprocess.STDOUT,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'},cwd=directory)
    except OSError:
        cfg.unlink(missing_ok=True);raise
    identity=hashlib.sha256(json.dumps([outbound,list(map(str,nets)),domains,req.get('dns','')],sort_keys=True).encode()).hexdigest()
    previous=SESSIONS.get(name,{})
    cached=list(previous.get('answers',[])) if previous.get('identity')==identity else []
    s=dict(identity=identity,cached_answers=cached,engine='singbox',process=process,log=log,reserved=nets,domains=domains,dns=req.get('dns',''),dns_via_vpn=bool(req.get('dns','')),owned=[],dev='',state='connecting',answers=[],started=time.time(),refreshed=0,stopping=False,challenge=None,local_ip=local_ip,remote_ip=peers[0],expected_dev=dev,peers=peers)
    SESSIONS[name]=s
    threading.Thread(target=monitor,args=(s,),daemon=True).start()
    return {'ok':True}

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            data = self.rfile.readline(2_100_000)
            if not data.endswith(b'\n'): raise ValueError('Invalid request size')
            with LOCK: result = dispatch(json.loads(data))
            response = {'result':result}
        except Exception as e: response = {'error':str(e)}
        self.wfile.write((json.dumps(response)+'\n').encode())

if __name__ == '__main__':
    if sys.platform != 'darwin' or os.geteuid() != 0: sys.exit('Requires macOS and sudo')
    uid = int(os.environ.get('SUDO_UID','0'))
    if not uid: sys.exit('Launch using sudo from your normal account')
    BINARY = sys.argv[1] if len(sys.argv)>1 else '/opt/homebrew/sbin/openvpn'
    if BINARY not in engine_paths('openvpn') or not os.path.isfile(BINARY): sys.exit('Pass the packaged or known Homebrew OpenVPN absolute path')
    # Hold a single-supervisor lock for the entire lifetime. Refuse legacy live
    # supervisors too, before recovering DNS files from a terminated process.
    import fcntl, stat
    lock_fd=os.open('/var/run/mochi.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    info=os.fstat(lock_fd)
    if info.st_uid!=0 or not stat.S_ISREG(info.st_mode):sys.exit('Unsafe helper lock')
    os.fchmod(lock_fd,0o600)
    try:fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:sys.exit('Mochi is already running. Close its dashboard first.')
    for previous in pathlib.Path('/var/run').glob('mochi-*/control.sock'):
        if previous.parent.stat().st_uid!=0:continue
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(.3)
            try:probe.connect(str(previous))
            except OSError:continue
            sys.exit('An older Mochi helper is still running. Close its dashboard first.')
    recovery=ResolverFiles(journal='/var/run/mochi-dns.json')
    try:recovery.recover()
    except Exception as e:sys.exit('DNS recovery requires review: '+str(e))
    running=run(['/bin/ps','-ax','-o','command=']).stdout.splitlines()
    if any(BINARY in line and '/var/run/mochi-' in line and 'client.ovpn' in line for line in running):
        sys.exit('An orphan Mochi OpenVPN process remains. Review its exact session and stop it before restarting.')
    if any('sing-box' in line and '/var/run/mochi-' in line and 'engine.json' in line for line in running):
        sys.exit('An orphan Mochi proxy process remains. Review its exact session before restarting.')
    SYSTEM_DNS, BASE_ROUTE = system_network()
    ROOT = tempfile.mkdtemp(prefix='mochi-',dir='/var/run'); os.chmod(ROOT,0o711)
    sock = ROOT+'/control.sock'
    server = socketserver.UnixStreamServer(sock,Handler); os.chown(sock,uid,-1); os.chmod(sock,0o600)
    if len(sys.argv)>2:
        watcher=int(sys.argv[2])
        if watcher<2:sys.exit('Invalid application supervisor')
        def watch_application():
            while not STOP.wait(2):
                try:os.kill(watcher,0)
                except ProcessLookupError:
                    server.shutdown();return
        threading.Thread(target=watch_application,daemon=True).start()
    print('Mochi socket: '+sock,flush=True)
    def stop(*_): raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop)
    try: server.serve_forever(poll_interval=.5)
    except KeyboardInterrupt: pass
    finally:
        STOP.set()
        with LOCK:
            for s in SESSIONS.values():
                try: disconnect(s)
                except Exception as e: print('CLEANUP REQUIRED:',e,file=sys.stderr)
        if DNS:
            try: DNS.close()
            except Exception as e: print('DNS CLEANUP REQUIRED:',e,file=sys.stderr)
        try: remove_bypass()
        except Exception as e: print('DIRECT CLEANUP REQUIRED:',e,file=sys.stderr)
        server.server_close()
        # Retain private logs for troubleshooting; credentials never go to IPC status.
        os.unlink(sock)
        print('Private session logs retained in '+ROOT)
