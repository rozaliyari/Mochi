import base64
import json
import os
import tempfile
import unittest
from unittest.mock import patch
import subscriptions as sub
from subscription_ui import private_json

URI='vless://00000000-0000-4000-8000-000000000001@8.8.8.8:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Fvpn#Example'


class SubscriptionTests(unittest.TestCase):
    def test_plain_and_base64_subscription_preserve_rows_and_names(self):
        data=URI+'\n'+URI.replace('#Example','#Second')
        for content in (data,base64.b64encode(data.encode()).decode()):
            rows=sub.parse(content)
            self.assertEqual([r['name'] for r in rows],['Example','Second'])
            self.assertEqual(rows[0]['outbound']['transport']['headers'],{'Host':'example.com'})

    def test_bad_rows_do_not_discard_other_servers_or_echo_credentials(self):
        rows=sub.parse(URI+'\nvless://SECRET@invalid')
        self.assertIn('outbound',rows[0]);self.assertIn('error',rows[1])
        self.assertNotIn('SECRET',str(rows))

    def test_plaintext_vless_and_insecure_tls_rejected(self):
        for uri in (URI.replace('security=tls','security=none'),URI+'&allowInsecure=1'):
            # Query must precede the fragment.
            if 'allowInsecure' in uri:uri=URI.replace('#Example','&allowInsecure=1#Example')
            self.assertIn('error',sub.parse(uri)[0])

    def test_unknown_transport_is_not_silently_downgraded(self):
        self.assertIn('error',sub.parse(URI.replace('type=ws','type=xhttp'))[0])

    def test_engine_json_is_rebuilt_without_arbitrary_paths_or_inbounds(self):
        o=sub.link(URI)['outbound']
        for key,value in [('bind_interface','en0'),('certificate_path','/etc/private'),('detour','other')]:
            with self.assertRaises(ValueError):sub.outbound(dict(o,**{key:value}))
        rows=sub.parse(json.dumps({'inbounds':[{'listen':'0.0.0.0'}],'outbounds':[o]}))
        self.assertEqual(rows[0]['outbound'],o)

    def test_no_default_routes_or_dns_hijack(self):
        config=sub.engine_config(sub.link(URI)['outbound'],'utun200','198.18.1.1/30','en0')
        self.assertFalse(config['inbounds'][0]['auto_route'])
        self.assertEqual(config['inbounds'][0]['dns_mode'],'disabled')
        self.assertEqual(config['route']['default_interface'],'en0')
        self.assertNotIn('experimental',config)

    def test_private_cache_permissions(self):
        with tempfile.TemporaryDirectory() as folder:
            from pathlib import Path
            p=Path(folder)/'private'/'cache.json'
            private_json(p,{'dummy':'value'})
            self.assertEqual(os.stat(p).st_mode&0o777,0o600)

    def test_private_and_loopback_server_dns_rejected_before_testing(self):
        row=sub.link(URI)
        with patch.object(sub.socket,'getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ValueError):sub.public_addresses('example.com',443)
            self.assertIsNone(sub.tcp_latency(row))

    def test_vmess_aead_link(self):
        data=dict(v='2',ps='VMess',add='8.8.8.8',port='443',id='00000000-0000-4000-8000-000000000001',aid='0',net='tcp',tls='tls',sni='example.com')
        row=sub.link('vmess://'+base64.b64encode(json.dumps(data).encode()).decode())
        self.assertEqual(row['outbound']['type'],'vmess')

    def test_input_limits(self):
        with self.assertRaises(ValueError):sub.parse('\n'.join([URI]*501))
        with self.assertRaises(ValueError):sub.parse(json.dumps([{}]*501))

    def test_failed_https_preflight_never_starts_a_routed_tunnel(self):
        import helper
        row=sub.link(URI)
        with patch.dict(helper.BASE_ROUTE,{'interface':'en0'},clear=True),patch.object(sub,'public_addresses',return_value=['8.8.8.8']),patch.object(sub,'real_latency',return_value=None),patch.object(helper.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(ValueError,'HTTPS connection test'):
                helper.connect_proxy(dict(name='test',outbound=row['outbound']),[],['*.example.com'])
            spawn.assert_not_called()

    def test_reality_and_grpc_conversion(self):
        uri=URI.replace('security=tls','security=reality&pbk='+'A'*43+'&sid=abcd&fp=chrome').replace('type=ws','type=grpc&serviceName=vpn')
        row=sub.link(uri)
        self.assertTrue(row['outbound']['tls']['reality']['enabled'])
        self.assertEqual(row['outbound']['transport'],dict(type='grpc',service_name='vpn'))

    def test_split_dns_retries_when_tcp_port_is_already_owned(self):
        import errno,socketserver
        from dns_rules import DNSService
        original=socketserver.ThreadingTCPServer.server_bind
        attempts=[]
        def bind(server):
            attempts.append(server.server_address)
            if len(attempts)==1:raise OSError(errno.EADDRINUSE,'occupied test port')
            return original(server)
        with tempfile.TemporaryDirectory() as folder,patch.object(socketserver.ThreadingTCPServer,'server_bind',bind):
            service=DNSService(lambda query,name:query,folder)
            try:
                self.assertEqual(len(attempts),2)
                self.assertEqual(service.udp.server_address[1],service.tcp.server_address[1])
            finally:service.close()
