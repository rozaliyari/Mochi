import pathlib
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch
from dns_rules import (DNSService, ResolverFiles, choose_rule, domain_rule,
                       error_answer, ipv4_answers, question, read_name, receive_exact)


def q(name='stage.example.com', kind=1):
    name=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
    return struct.pack('!6H',123,0x100,1,0,0,0)+name+struct.pack('!HH',kind,1)


def a(query, address='10.20.1.5', extra=False):
    header=struct.pack('!6H',123,0x8180,1,1,0,int(extra))
    answer=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton(address)
    if extra:
        answer+=b'\x03bad\x07example\x03com\0'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('10.99.1.1')
    return header+query[12:]+answer


class DNSRulesTests(unittest.TestCase):
    def test_suffix_boundary_exact_and_direct_precedence(self):
        rules=[('*.example.com','project'),('*.public.example.com','DIRECT'),('one.public.example.com','special')]
        self.assertEqual(choose_rule(rules,'example.com'),'project')
        self.assertEqual(choose_rule(rules,'a.example.com'),'project')
        self.assertEqual(choose_rule(rules,'b.public.example.com'),'DIRECT')
        self.assertEqual(choose_rule(rules,'one.public.example.com'),'special')
        self.assertIsNone(choose_rule(rules,'notexample.com'))
        self.assertIsNone(choose_rule([('a.example.com','one')],'b.a.example.com'))
        for bad in ['https://example.com','../x','*.com','x;rm.com','example.com/path']:
            with self.assertRaises(ValueError):domain_rule(bad)

    def test_response_question_and_id_must_match(self):
        query=q();response=a(query)
        self.assertEqual(ipv4_answers(response,query),{'10.20.1.5'})
        self.assertEqual(ipv4_answers(a(query,extra=True),query),{'10.20.1.5'})
        with self.assertRaises(ValueError):ipv4_answers(b'zz'+response[2:],query)
        with self.assertRaises(ValueError):ipv4_answers(response,q('other.example.com'))
        with self.assertRaises(ValueError):read_name(b'\xc0\x00',0)

    def test_cname_follows_only_the_answer_chain(self):
        query=q(); target=b'\x06target\x07example\x03com\0'
        cname=b'\xc0\x0c'+struct.pack('!HHIH',5,1,30,len(target))+target
        record=target+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('10.20.2.3')
        response=struct.pack('!6H',123,0x8180,1,2,0,0)+query[12:]+cname+record
        self.assertEqual(ipv4_answers(response,query),{'10.20.2.3'})

    def test_owned_files_only_and_transactional_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            files=ResolverFiles(tmp)
            files.install(['*.example.com'],53000)
            path=pathlib.Path(tmp)/'example.com'
            self.assertIn(b'port 53000',path.read_bytes())
            other=pathlib.Path(tmp)/'other.com';other.write_text('user settings')
            with self.assertRaises(FileExistsError):files.install(['*.example.com','other.com'],53000)
            self.assertEqual(other.read_text(),'user settings')
            path.write_text('user edited it')
            with self.assertRaises(RuntimeError):files.close()
            self.assertEqual(path.read_text(),'user edited it')

    def test_udp_and_tcp_local_queries_and_fail_closed_route_error(self):
        calls=[]
        def handle(query,name):
            calls.append(name)
            return a(query)
        with tempfile.TemporaryDirectory() as tmp:
            service=DNSService(handle,tmp)
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.settimeout(2);client.sendto(q(),('127.0.0.1',service.port))
                    self.assertEqual(ipv4_answers(client.recv(4096),q()),{'10.20.1.5'})
                    client.sendto(q(kind=28),('127.0.0.1',service.port))
                    self.assertEqual(struct.unpack('!6H',client.recv(4096)[:12])[3],0)
                with socket.create_connection(('127.0.0.1',service.port),timeout=2) as client:
                    query=q();client.sendall(struct.pack('!H',len(query))+query)
                    response=receive_exact(client,struct.unpack('!H',receive_exact(client,2))[0])
                    self.assertEqual(ipv4_answers(response,query),{'10.20.1.5'})
                def reject(query,name):raise ValueError('Conflicting route')
                service.handle=reject
                response=service.answer(q())
                self.assertEqual(response[3]&15,2)
                self.assertEqual(service.last_error,'Conflicting route')
                self.assertEqual(len(calls),2)  # AAAA never reached the upstream.
            finally:service.close()

    def test_resolution_commits_routes_before_answer(self):
        import helper
        from unittest.mock import Mock
        session=dict(state='connected',stopping=False,dev='utun8',domains=['*.example.com'],dns='10.20.0.53',answers=[],reserved=[],owned=[],process=Mock())
        session['process'].poll.return_value=None
        with patch.dict(helper.SESSIONS,{'one':session},clear=True),patch.dict(helper.DIRECT,{'domains':[],'cidrs':[]},clear=True),patch.object(helper,'upstream_query',return_value=a(q())),patch.object(helper,'add_route') as route:
            result=helper.resolve_domain(q(),'stage.example.com')
            route.assert_called_once()
            self.assertEqual(ipv4_answers(result,q()),{'10.20.1.5'})
            route.side_effect=ValueError('overlap')
            with self.assertRaises(ValueError):helper.resolve_domain(q(),'stage.example.com')

class RecoveryTests(unittest.TestCase):
    def test_stale_resolvers_recover_without_touching_user_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal=pathlib.Path(tmp)/'state.json';directory=pathlib.Path(tmp)/'resolver'
            first=ResolverFiles(directory,journal)
            first.install(['*.example.com'],53000)
            user=directory/'user.com';user.write_text('nameserver 10.1.1.1')
            recovered=ResolverFiles(directory,journal);recovered.recover()
            self.assertFalse((directory/'example.com').exists())
            self.assertTrue(user.exists())
            self.assertEqual(journal.read_text(),'{}')
