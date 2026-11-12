"""Strict, deliberately limited OpenVPN profile and routing policy."""
import ipaddress, re, shlex

ALLOWED = set('client tls-client remote proto port nobind resolv-retry remote-random remote-random-hostname auth cipher data-ciphers data-ciphers-fallback tls-cipher tls-ciphersuites tls-version-min remote-cert-tls verify-x509-name key-direction reneg-sec connect-retry connect-timeout server-poll-timeout ping ping-restart mute auth-nocache explicit-exit-notify tun-mtu mssfix persist-key'.split())
BLOCKS = {'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2'}

def sanitize(text):
    if len(text.encode()) > 2_000_000: raise ValueError('Profile too large')
    out, block, seen = [], None, set()
    auth_none = False
    bare_auth = False
    crypto = {}
    for raw in text.splitlines():
        line = raw.strip()
        if block:
            out.append(raw)
            if line == '</'+block+'>': block = None
            continue
        if not line or line.startswith(('#', ';')): continue
        if line.startswith('<'):
            tag = line[1:-1]
            if tag not in BLOCKS: raise ValueError('Unsupported inline block: '+line)
            block = tag; seen.add(tag); out.append(line); continue
        words = shlex.split(line, comments=True)
        if not words: continue
        key = words[0]
        # Portable least-privilege accounts. Linux exports often use nogroup;
        # macOS provides nobody. Never honor a profile requesting root/wheel.
        if key in {'user', 'group'}:
            accounts = {'user': {'nobody', '_nobody', 'openvpn', '_openvpn'},
                        'group': {'nobody', '_nobody', 'nogroup', 'openvpn', '_openvpn'}}
            if len(words) != 2 or words[1] not in accounts[key]:
                raise ValueError('Unsupported '+key+' account; supported unprivileged accounts are mapped to macOS nobody')
            out.append(key+' nobody'); seen.add(key); continue
        if key == 'auth-user-pass':
            if len(words) != 1: raise ValueError('External password files are not imported. Use a bare auth-user-pass directive and enter credentials in Mochi.')
            out.append('auth-user-pass'); seen.add(key); continue
        if key == 'static-challenge':
            if len(words)!=3 or words[2] not in {'0','1'} or len(words[1])>1000: raise ValueError('Unsupported static challenge format')
            out.append(line); continue
        if key=='mute':
            if len(words)!=2 or not words[1].isdigit():raise ValueError('mute requires a nonnegative integer')
            # Keep connection/interface/error messages visible to diagnostics.
            continue
        if key in {'pull', 'mute-replay-warnings'}:
            if len(words)!=1: raise ValueError('Unexpected arguments for '+key)
            # client already enables pull. Keep replay warnings visible.
            continue
        if key == 'dev' and words[1:] == ['tun']: continue
        if key in {'route', 'route-ipv6', 'route-nopull', 'route-noexec', 'redirect-gateway', 'redirect-private', 'dhcp-option', 'persist-tun', 'verb'}: continue
        if key not in ALLOWED: raise ValueError('Unsupported OpenVPN option: '+key+'. This option has not been enabled in Mochi.')
        if any('\x00' in v or '\n' in v for v in words): raise ValueError('Invalid directive')
        if key == 'remote-cert-tls' and words[1:] != ['server']: raise ValueError('Server certificate verification is required')
        if key == 'auth':
            if len(words)==1:
                # Some OpenVPN Connect exports contain a redundant empty auth
                # directive followed by an explicit digest. OpenVPN 2 rejects it.
                bare_auth=True;continue
            if len(words)!=2:raise ValueError('auth requires exactly one digest')
            if words[1]=='none':auth_none=True
        if key in {'cipher','data-ciphers','data-ciphers-fallback'}:
            if len(words)!=2: raise ValueError('Invalid cipher directive')
            values=words[1].split(':')
            if any(v.lower()=='none' for v in values): raise ValueError('Null encryption is forbidden')
            crypto.setdefault(key,[]).extend(values)
        seen.add(key); out.append(line)
    if block: raise ValueError('Unclosed inline certificate block')
    if bare_auth and 'auth' not in seen:raise ValueError('An empty auth directive requires an explicit auth digest in the profile')
    if not {'remote', 'ca'} <= seen: raise ValueError('An inline CA and remote are required')
    if auth_none:
        aead={'AES-128-GCM','AES-192-GCM','AES-256-GCM','CHACHA20-POLY1305'}
        if 'tls-auth' in seen or any(v not in aead for choices in crypto.values() for v in choices):
            raise ValueError('auth none is supported only with AEAD-only ciphers and without tls-auth')
        if 'data-ciphers' not in crypto:
            choices=crypto.get('cipher',['AES-256-GCM','AES-128-GCM','CHACHA20-POLY1305'])
            out.append('data-ciphers '+':'.join(choices))
    if not auth_none and 'data-ciphers' not in crypto and 'cipher' in crypto:
        choices=['AES-256-GCM','AES-128-GCM','CHACHA20-POLY1305']
        choices+= [v for v in crypto['cipher'] if v not in choices]
        out.append('data-ciphers '+':'.join(choices))
    if 'user' in seen and 'group' not in seen: out.append('group nobody')
    if 'remote-cert-tls' not in seen: out.append('remote-cert-tls server')
    return '\n'.join(out)+'\n'

def network(value):
    n = ipaddress.ip_network(value.strip(), strict=True)
    if n.version != 4 or n.prefixlen < 8 or n.is_multicast or n.is_loopback or n.is_link_local or n.is_unspecified:
        raise ValueError('Use an IPv4 destination CIDR with prefix /8–/32; default, multicast, loopback and link-local routes are forbidden')
    forbidden = ['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4']
    if any(n.overlaps(ipaddress.ip_network(f)) for f in forbidden): raise ValueError('Special-use destination range is forbidden')
    return n

def policy(cidrs, domains, dns):
    nets = [network(x) for x in cidrs]
    from dns_rules import domain_rule
    names = list(dict.fromkeys(domains))
    for d in names: domain_rule(d)
    if dns.strip():
        try: a = ipaddress.IPv4Address(dns)
        except ValueError: raise ValueError('VPN DNS must be an IPv4 address, or left empty for automatic selection.') from None
        nets.append(network(str(a)+'/32'))
    if not nets and not names:
        raise ValueError('Add at least one Destination CIDR or domain rule before connecting.')
    return nets, names

def conflicts(nets, others):
    for n in nets:
        for o in others:
            if n.overlaps(o): raise ValueError(f'Overlapping destinations: {n} and {o}')


def suggested_routes(text):
    """Read only plain IPv4 VPN destination routes; never infer default routes."""
    routes=[];block=None
    for raw in text.splitlines():
        line=raw.strip()
        if block:
            if line=='</'+block+'>':block=None
            continue
        if line.startswith('<'):block=line[1:-1];continue
        if not line or line.startswith(('#',';')):continue
        words=shlex.split(line,comments=True)
        if not words or words[0]!='route' or len(words) not in (3,4):continue
        if len(words)==4 and words[3]!='vpn_gateway':continue
        try:n=network(str(ipaddress.IPv4Network(words[1]+'/'+words[2],strict=True)))
        except ValueError:continue
        if str(n) not in routes:routes.append(str(n))
    return routes


def override_server(profile, host):
    """Preserve provider TLS material and remote ports/protocols; replace host only."""
    host=host.strip()
    if not host:return profile
    try:
        address=ipaddress.ip_address(host)
        if address.version!=4:raise ValueError('IPv4 server required')
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',host):
            raise ValueError('Server Override must be an IPv4 address or hostname, without URL, spaces or paths')
    out=[];block=None
    for line in profile.splitlines():
        if block:
            out.append(line)
            if line.strip()=='</'+block+'>':block=None
        elif line.startswith('<'):
            block=line[1:-1];out.append(line)
        elif line.startswith('remote '):
            words=shlex.split(line,comments=True)
            out.append('remote '+host+(' '+' '.join(words[2:]) if len(words)>2 else ''))
        else:out.append(line)
    return sanitize('\n'.join(out)+'\n')
