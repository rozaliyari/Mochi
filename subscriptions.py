"""Bounded subscription import. Only supported outbound settings enter the engine."""
import base64
import concurrent.futures
import http.client
import ipaddress
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_BYTES = 2_000_000
MAX_SERVERS = 500
from runtime_paths import engine_paths,bundle_contents
BINARY_PATHS = engine_paths('sing-box')


def binary():
    for path in BINARY_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    if bundle_contents():raise ValueError('The packaged connection engine is missing or damaged. Reinstall Mochi.')
    raise ValueError('Install the connection engine first: brew install sing-box')


def text(value, limit=1024):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid configuration text')
    return value


def host(value):
    value = text(value, 253).strip()
    try:
        address = ipaddress.ip_address(value)
        if address.version != 4 or not address.is_global:
            raise ValueError('Only public IPv4 server addresses are supported')
        return str(address)
    except ValueError:
        import re
        if not value or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value) or '.' not in value:
            raise ValueError('Invalid public server hostname')
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
        raise ValueError('Only public IPv4 server addresses are supported')


def public_addresses(server, port):
    addresses = list(dict.fromkeys(r[4][0] for r in socket.getaddrinfo(server, port, socket.AF_INET, socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('Server DNS must resolve only to public IPv4 addresses')
    return addresses


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Subscription redirected. Import the final HTTPS URL explicitly.')


def fetch(url):
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Use a complete HTTPS subscription URL')
    addresses=public_addresses(parsed.hostname, parsed.port or 443)
    connection=http.client.HTTPSConnection(parsed.hostname,parsed.port or 443,timeout=20)
    # Preserve certificate/SNI verification while pinning the public address we
    # checked. Rebinding cannot turn an import into a request to a private host.
    connection._create_connection=lambda address,timeout,source_address=None:socket.create_connection((addresses[0],parsed.port or 443),timeout,source_address)
    try:
        target=urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
        connection.request('GET',target,headers={'User-Agent':'Mochi/0.8 Subscription'})
        response=connection.getresponse()
        if 300<=response.status<400:raise ValueError('Subscription redirected. Import the final HTTPS URL explicitly.')
        if response.status!=200:raise ValueError('Subscription server returned HTTP '+str(response.status))
        data=response.read(MAX_BYTES+1)
    except (http.client.HTTPException, OSError):
        raise ValueError('Cannot download subscription. Check your connection and subscription validity.') from None
    finally:connection.close()
    if len(data) > MAX_BYTES:
        raise ValueError('Subscription is too large')
    return parse(data.decode('utf-8-sig'))


def decode64(value):
    value = ''.join(value.split())
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True).decode('utf-8-sig')


def outbound(data):
    """Rebuild a minimal outbound; arbitrary engine config cannot pass through."""
    if not isinstance(data, dict) or data.get('type') not in ('vless', 'vmess'):
        raise ValueError('Only VLESS and VMess outbounds are supported')
    allowed = {'type', 'server', 'server_port', 'uuid', 'flow', 'security', 'alter_id', 'tls', 'transport', 'tag'}
    if set(data) - allowed:
        raise ValueError('Unsupported outbound settings; import a standard VLESS/VMess share link')
    result = dict(type=data['type'], tag='vpn', server=host(data.get('server', '')),
                  server_port=int(data.get('server_port', 0)), uuid=str(uuid.UUID(data.get('uuid', ''))))
    if not 1 <= result['server_port'] <= 65535:
        raise ValueError('Invalid server port')
    if result['type'] == 'vless':
        flow = data.get('flow', '')
        if flow not in ('', 'xtls-rprx-vision'):
            raise ValueError('Unsupported VLESS flow')
        if flow:
            result['flow'] = flow
    else:
        if int(data.get('alter_id', 0)) != 0:
            raise ValueError('Legacy VMess alterId is unsupported')
        security = data.get('security', 'auto')
        if security not in ('auto', 'aes-128-gcm', 'chacha20-poly1305'):
            raise ValueError('VMess requires authenticated encryption')
        result.update(security=security, alter_id=0)
    tls = data.get('tls')
    if tls:
        if not isinstance(tls, dict) or set(tls) - {'enabled', 'server_name', 'insecure', 'alpn', 'utls', 'reality'}:
            raise ValueError('Unsupported TLS settings')
        if tls.get('insecure') or not tls.get('enabled', True):
            raise ValueError('Insecure TLS is not allowed')
        checked = dict(enabled=True, server_name=host(tls.get('server_name') or result['server']))
        if tls.get('alpn'):
            if not isinstance(tls['alpn'], list) or len(tls['alpn']) > 8:
                raise ValueError('Invalid TLS ALPN')
            checked['alpn'] = [text(x, 40) for x in tls['alpn']]
        if tls.get('utls'):
            u = tls['utls']
            if not isinstance(u, dict) or set(u) - {'enabled', 'fingerprint'}:
                raise ValueError('Invalid TLS fingerprint')
            fp = u.get('fingerprint', 'chrome')
            if fp not in ('chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'):
                raise ValueError('Unsupported TLS fingerprint')
            checked['utls'] = dict(enabled=True, fingerprint=fp)
        if tls.get('reality'):
            import re
            r = tls['reality']
            if not isinstance(r, dict) or set(r) - {'enabled', 'public_key', 'short_id'}:
                raise ValueError('Invalid Reality settings')
            key, sid = r.get('public_key', ''), r.get('short_id', '')
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key) or not re.fullmatch(r'(?:[a-fA-F0-9]{2}){0,8}', sid):
                raise ValueError('Invalid Reality public key / short ID')
            checked['reality'] = dict(enabled=True, public_key=key, short_id=sid)
        result['tls'] = checked
    if result['type'] == 'vless' and not tls:
        raise ValueError('VLESS requires TLS or Reality')
    transport = data.get('transport')
    if transport:
        if not isinstance(transport, dict):
            raise ValueError('Invalid transport')
        kind = transport.get('type')
        if kind not in ('ws', 'grpc', 'httpupgrade'):
            raise ValueError('Unsupported transport (TCP, WS, gRPC and HTTPUpgrade are supported)')
        if set(transport) - {'type', 'path', 'headers', 'service_name', 'host'}:
            raise ValueError('Unsupported transport options')
        t = dict(type=kind)
        if kind == 'grpc':
            t['service_name'] = text(transport.get('service_name', ''))
        else:
            t['path'] = text(transport.get('path') or '/')
            if kind == 'ws' and transport.get('headers'):
                headers = transport['headers']
                if not isinstance(headers, dict) or set(headers) != {'Host'}:
                    raise ValueError('Only the WebSocket Host header is supported')
                t['headers'] = {'Host': text(headers['Host'], 253)}
            if kind == 'httpupgrade':
                t['host'] = text(transport.get('host', ''), 253)
        result['transport'] = t
    return result


def link(uri):
    p = urllib.parse.urlsplit(uri)
    if p.scheme == 'vmess':
        v = json.loads(decode64(uri[len('vmess://'):]))
        name = v.get('ps') or 'VMess'
        q = dict(type='vmess', server=v.get('add'), server_port=v.get('port'), uuid=v.get('id'),
                 alter_id=v.get('aid', 0), security=v.get('scy') or 'auto')
        params = dict(type=v.get('net') or 'tcp', security=v.get('tls') or 'none',
                      sni=v.get('sni') or v.get('host') or v.get('add'), fp=v.get('fp') or '',
                      path=v.get('path') or '/', host=v.get('host') or '', serviceName=v.get('path') or '')
    elif p.scheme == 'vless':
        if p.password or not p.hostname or not p.username:
            raise ValueError('Invalid VLESS link')
        params = {k: values[-1] for k, values in urllib.parse.parse_qs(p.query, keep_blank_values=True).items()}
        if params.get('encryption', 'none') != 'none':
            raise ValueError('Unsupported VLESS encryption')
        name = urllib.parse.unquote(p.fragment) or 'VLESS'
        q = dict(type='vless', server=p.hostname, server_port=p.port, uuid=urllib.parse.unquote(p.username), flow=params.get('flow', ''))
    else:
        raise ValueError('Unsupported protocol')
    if params.get('allowInsecure') in ('1', 'true') or params.get('insecure') in ('1', 'true'):
        raise ValueError('Insecure TLS is not allowed')
    security = params.get('security', 'none')
    if security in ('tls', 'reality'):
        t = dict(enabled=True, server_name=params.get('sni') or params.get('serverName') or q['server'])
        if params.get('alpn'):
            t['alpn'] = params['alpn'].split(',')
        if params.get('fp'):
            t['utls'] = dict(enabled=True, fingerprint=params['fp'])
        if security == 'reality':
            t['reality'] = dict(enabled=True, public_key=params.get('pbk', ''), short_id=params.get('sid', ''))
            t.setdefault('utls', dict(enabled=True, fingerprint='chrome'))
        q['tls'] = t
    elif security not in ('', 'none'):
        raise ValueError('Unsupported TLS mode')
    kind = params.get('type', 'tcp')
    if kind in ('tcp','raw','') and params.get('headerType','none') not in ('','none'):
        raise ValueError('Custom TCP headers are unsupported')
    if kind not in ('tcp', 'raw', ''):
        q['transport'] = dict(type=kind)
        if kind == 'grpc':
            q['transport']['service_name'] = params.get('serviceName', '')
        else:
            q['transport']['path'] = params.get('path') or '/'
            if params.get('host'):
                if kind == 'httpupgrade': q['transport']['host'] = params['host']
                else: q['transport']['headers'] = {'Host': params['host']}
    return dict(name=text(str(name), 512), outbound=outbound(q))


def parse(content):
    if len(content.encode()) > MAX_BYTES:
        raise ValueError('Subscription is too large')
    content = content.strip()
    if not content.startswith(('{', '[', 'vless://', 'vmess://')):
        try: content = decode64(content)
        except (ValueError, UnicodeError): raise ValueError('Expected subscription links or JSON, received another format') from None
    if content.startswith(('{', '[')):
        data = json.loads(content)
        entries = data if isinstance(data, list) else data.get('outbounds', [data])
        if not isinstance(entries, list): raise ValueError('Invalid outbound list')
        if len(entries)>MAX_SERVERS:raise ValueError('Subscription has more than 500 servers')
        rows = []
        for item in entries[:MAX_SERVERS]:
            try: rows.append(dict(name=text(item.get('tag') or 'VLESS / VMess', 512), outbound=outbound(item)))
            except (ValueError, TypeError, AttributeError): rows.append(dict(name='Unsupported JSON outbound', error='Unsupported or unsafe outbound settings'))
    else:
        lines = [s.strip() for s in content.splitlines() if s.strip()]
        if len(lines) > MAX_SERVERS: raise ValueError('Subscription has more than 500 servers')
        rows = []
        for i, uri in enumerate(lines):
            try: rows.append(link(uri))
            except (ValueError, TypeError, KeyError, AttributeError) as e:
                # Never display raw parser errors: they may include credential material.
                rows.append(dict(name='Unsupported server ' + str(i + 1), error='Unsupported transport, invalid settings or insecure TLS'))
    if not rows: raise ValueError('No server found in subscription')
    return rows


def tcp_latency(row, timeout=3):
    if 'outbound' not in row: return None
    o = row['outbound']
    try:
        addresses = public_addresses(o['server'], o['server_port'])
        start = time.monotonic()
        with socket.create_connection((addresses[0], o['server_port']), timeout):
            return round((time.monotonic() - start) * 1000)
    except (OSError, ValueError): return None


def engine_config(o, interface=None, address=None, physical=None, socks_port=None):
    o = outbound(o)
    route = dict(final='vpn')
    if physical: route['default_interface'] = physical
    if interface:
        inbound = dict(type='tun', interface_name=interface, address=[address], auto_route=False,
                       dns_mode='disabled', stack='gvisor', mtu=1400)
    else:
        inbound = dict(type='socks', listen='127.0.0.1', listen_port=socks_port)
    return dict(log=dict(level='warn', timestamp=True), inbounds=[inbound], outbounds=[o], route=route)


def real_latency(row, timeout=8):
    """HTTPS via a private temporary SOCKS engine. Never changes macOS routes."""
    if 'outbound' not in row: return None
    process = None
    try:
        o = dict(row['outbound'])
        o['server'] = public_addresses(o['server'], o['server_port'])[0]
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0)); port = s.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='mochi-test-') as folder:
            path = pathlib.Path(folder)/'engine.json'
            fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f: json.dump(engine_config(o, socks_port=port), f)
            process = subprocess.Popen([binary(), 'run', '-c', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(40):
                if process.poll() is not None: return None
                try:
                    with socket.create_connection(('127.0.0.1', port), .1): break
                except OSError: time.sleep(.05)
            result = subprocess.run(['/usr/bin/curl', '--silent', '--fail', '--output', '/dev/null',
                                     '--write-out', '%{time_total}', '--proxy', f'socks5h://127.0.0.1:{port}',
                                     '--max-time', str(timeout), 'https://www.gstatic.com/generate_204'],
                                    capture_output=True, timeout=timeout+2)
            if result.returncode == 0: return round(float(result.stdout)*1000)
    except (OSError, ValueError, subprocess.TimeoutExpired): pass
    finally:
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(3)
            except subprocess.TimeoutExpired: process.kill(); process.wait()
    return None
