"""Small split-DNS server. Only loopback clients; routes are committed before answers.

No third-party DNS library. One IN question, bounded compression parsing, A/CNAME
answers only. DNSSEC is not asserted after suppressing IPv6 answers (IPv4 MVP).
"""
import ipaddress
import json
import tempfile
import os
import pathlib
import re
import secrets
import socket
import socketserver
import struct
import threading


def domain_rule(text):
    text = text.strip().lower().rstrip('.')
    suffix = text.startswith('*.')
    name = text[2:] if suffix else text
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', name):
        raise ValueError('Use a domain such as stage.example.com or *.example.com; omit https:// and paths.')
    return name, suffix


def matches(rule, name):
    base, suffix = domain_rule(rule)
    return name == base or suffix and name.endswith('.' + base)


def choose_rule(rules, name):
    candidates = [(len(domain_rule(r)[0]), not domain_rule(r)[1], owner)
                  for r, owner in rules if matches(r, name)]
    return max(candidates)[2] if candidates else None


def read_name(data, offset):
    labels, visited, end = [], set(), None
    for _ in range(128):
        if offset >= len(data) or offset in visited:
            raise ValueError('Invalid DNS name')
        visited.add(offset)
        length = data[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(data): raise ValueError('Short DNS pointer')
            if end is None: end = offset + 2
            offset = ((length & 63) << 8) | data[offset + 1]
            continue
        if length & 0xc0 or length > 63: raise ValueError('Invalid DNS label')
        offset += 1
        if length == 0:
            name = '.'.join(labels).lower()
            if len(name) > 253: raise ValueError('DNS name too long')
            return name, end if end is not None else offset
        if offset + length > len(data): raise ValueError('Short DNS label')
        labels.append(data[offset:offset + length].decode('ascii'))
        offset += length
    raise ValueError('Too many DNS labels')


def question(data):
    if len(data) < 12: raise ValueError('Short DNS packet')
    ident, flags, count, _, _, _ = struct.unpack('!6H', data[:12])
    if count != 1 or flags & 0x8000 or flags & 0x7800:
        raise ValueError('One standard DNS question required')
    name, end = read_name(data, 12)
    if end + 4 > len(data): raise ValueError('Short DNS question')
    kind, cls = struct.unpack('!HH', data[end:end + 4])
    if cls != 1: raise ValueError('Only IN DNS supported')
    return ident, name, kind, end + 4


def make_query(name):
    base,_=domain_rule(name)
    wire=b''.join(bytes([len(label)])+label.encode('ascii') for label in base.split('.'))+b'\0'
    return secrets.token_bytes(2)+struct.pack('!5H',0x100,1,0,0,0)+wire+struct.pack('!HH',1,1)


def error_answer(query, code=2):
    ident, _, _, end = question(query)
    return struct.pack('!6H', ident, 0x8180 | code, 1, 0, 0, 0) + query[12:end]


def ipv4_answers(response, query):
    ident, name, kind, _ = question(query)
    if len(response) < 12: raise ValueError('Short DNS response')
    rid, flags, qd, an, ns, ar = struct.unpack('!6H', response[:12])
    if rid != ident or not flags & 0x8000 or flags & 0x0200 or qd != 1:
        raise ValueError('Mismatched or truncated DNS response')
    rn, pos = read_name(response, 12)
    if pos + 4 > len(response) or rn != name or response[pos:pos+4] != struct.pack('!HH', kind, 1):
        raise ValueError('Mismatched DNS question')
    pos += 4
    if an + ns + ar > 2048: raise ValueError('Too many DNS records')
    addresses, aliases = {}, {}
    for i in range(an + ns + ar):
        owner, pos = read_name(response, pos)
        if pos + 10 > len(response): raise ValueError('Short DNS record')
        typ, cls, ttl, size = struct.unpack('!HHIH', response[pos:pos+10]); pos += 10
        if pos + size > len(response): raise ValueError('Short DNS data')
        if i < an and cls == 1:
            if typ == 1 and size == 4:
                addresses.setdefault(owner, set()).add(str(ipaddress.IPv4Address(response[pos:pos+4])))
            elif typ == 5:
                alias, consumed = read_name(response, pos)
                if consumed != pos + size: raise ValueError('Invalid CNAME')
                aliases[owner] = alias
        pos += size
    # Do not install routes from unrelated answer/additional records.
    found, seen, current = set(), set(), name
    while current not in seen:
        seen.add(current); found.update(addresses.get(current, ()))
        if current not in aliases: break
        current = aliases[current]
    if len(seen) > 32: raise ValueError('CNAME chain too long')
    return found


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise OSError('DNS TCP closed')
        data.extend(chunk)
    return bytes(data)


def upstream_query(query, address):
    # Connected UDP validates the response source; unpredictable IDs resist spoofing.
    original = query[:2]
    wire = secrets.token_bytes(2) + query[2:]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4); s.connect((address, 53)); s.send(wire); result = s.recv(65535)
    if len(result) < 12 or result[:2] != wire[:2]: raise OSError('Invalid DNS upstream reply')
    if result[2] & 2:  # TC: retry over TCP
        with socket.create_connection((address, 53), timeout=4) as s:
            s.sendall(struct.pack('!H', len(wire)) + wire)
            result = receive_exact(s, struct.unpack('!H', receive_exact(s, 2))[0])
        if len(result) < 12 or result[:2] != wire[:2]: raise OSError('Invalid DNS TCP reply')
    result = original + result[2:]
    ipv4_answers(result, query)  # Validate before returning even negative answers.
    return result


class ResolverFiles:
    """Never overwrite an existing resolver, symlink, or another app's file."""
    def __init__(self, directory='/etc/resolver', journal=None):
        self.directory = pathlib.Path(directory)
        self.owned = {}
        self.journal=pathlib.Path(journal) if journal else None
        self.marker = '# Mochi ' + secrets.token_hex(16)

    def persist(self):
        if not self.journal:return
        fd,tmp=tempfile.mkstemp(dir=self.journal.parent)
        try:
            with os.fdopen(fd,'w') as f:json.dump({k:v.decode() for k,v in self.owned.items()},f)
            os.replace(tmp,self.journal)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)

    def recover(self):
        if not self.journal or not self.journal.exists():return
        if self.journal.is_symlink():raise RuntimeError('Unsafe DNS recovery journal')
        data=json.loads(self.journal.read_text())
        for name,content in data.items():
            if domain_rule(name)[0]!=name or not content.startswith('# Mochi '):
                raise RuntimeError('Invalid DNS recovery journal')
        self.owned={k:v.encode() for k,v in data.items()}
        self.close()

    def install(self, domains, port):
        self.directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        if self.directory.is_symlink(): raise ValueError('Resolver directory must not be a symlink')
        wanted = {domain_rule(d)[0] for d in domains}
        added = []
        try:
            for name in wanted - self.owned.keys():
                data = f'{self.marker}\nnameserver 127.0.0.1\nport {port}\ntimeout 2\n'.encode()
                path = self.directory / name
                self.owned[name]=data
                self.persist()  # Journal before creating a resolver, including crash recovery.
                try: fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                except BaseException:
                    self.owned.pop(name,None);self.persist();raise
                try:
                    with os.fdopen(fd, 'wb') as f: f.write(data)
                except BaseException:
                    path.unlink(); raise
                self.owned[name] = data; added.append(name)
        except BaseException:
            for name in added: self.remove(name)
            raise
        for name in list(self.owned):
            if name not in wanted: self.remove(name)

    def remove(self, name):
        path = self.directory / name
        # Only unlink our original content. A user edit is never deleted.
        if path.is_symlink(): raise RuntimeError('Resolver changed; manual cleanup required: ' + name)
        try:
            if path.read_bytes() != self.owned[name]:
                raise RuntimeError('Resolver changed; manual cleanup required: ' + name)
            path.unlink()
        except FileNotFoundError: pass
        self.owned.pop(name, None)
        self.persist()

    def close(self):
        errors = []
        for name in list(self.owned):
            try: self.remove(name)
            except Exception as e: errors.append(str(e))
        if errors: raise RuntimeError('; '.join(errors))


class DNSService:
    def __init__(self, handle, directory='/etc/resolver', journal=None):
        self.handle = handle
        self.last_error = ''
        self.slots = threading.BoundedSemaphore(32)
        self.files = ResolverFiles(directory,journal)
        service = self
        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                if not service.slots.acquire(blocking=False): return
                try:
                    data, sock = self.request
                    result = service.answer(data)
                    if result is not None: sock.sendto(result, self.client_address)
                finally: service.slots.release()
        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                if not service.slots.acquire(blocking=False): return
                try:
                    self.request.settimeout(8)
                    size = struct.unpack('!H', receive_exact(self.request, 2))[0]
                    if size > 16384: return
                    result = service.answer(receive_exact(self.request, size))
                    if result is not None: self.request.sendall(struct.pack('!H', len(result)) + result)
                except OSError: pass
                finally: service.slots.release()
        class UDPServer(socketserver.ThreadingUDPServer): daemon_threads = True
        class TCPServer(socketserver.ThreadingTCPServer): daemon_threads = True
        # UDP ephemeral allocation does not reserve the same TCP port. Pick
        # another pair when a TCP listener/TIME_WAIT entry already owns it.
        import errno
        for attempt in range(10):
            self.udp = UDPServer(('127.0.0.1', 0), UDP)
            self.port = self.udp.server_address[1]
            try:
                self.tcp = TCPServer(('127.0.0.1', self.port), TCP)
                break
            except OSError as e:
                self.udp.server_close()
                if e.errno!=errno.EADDRINUSE or attempt==9:raise
            except BaseException:
                self.udp.server_close();raise
        for server in (self.udp, self.tcp):
            threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True).start()

    def answer(self, query):
        try:
            _, name, kind, _ = question(query)
            # Selected domains are IPv4 only. Suppress AAAA and HTTPS/SVCB address
            # hints, so system-resolver clients cannot choose an unrouted IPv6 IP.
            if kind not in (1, 5): return error_answer(query, 0)
            result=self.handle(query,name)
            self.last_error=''
            return result
        except (ValueError, OSError, RuntimeError) as e:
            self.last_error=str(e)[:300]
            try: return error_answer(query)
            except ValueError: return None

    def close(self):
        try:self.files.close()
        finally:
            for server in (self.udp,self.tcp):
                server.shutdown();server.server_close()
