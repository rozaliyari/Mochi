import unittest
from core import sanitize, network, policy, conflicts, suggested_routes
BASE='client\ndev tun\nremote vpn.example.org 1194\n<ca>\ncertificate\n</ca>\n'
class PolicyTests(unittest.TestCase):
    def test_scripts_and_indirect_configs_rejected(self):
        for option in ['up /tmp/a','plugin /tmp/a','config /tmp/a','management 127.0.0.1 7505','auth-user-pass /tmp/p','ca /tmp/a','setenv opt x','dev tap']:
            with self.subTest(option=option), self.assertRaises(ValueError): sanitize(BASE+option)
    def test_default_and_server_routes_removed(self):
        result=sanitize(BASE+'redirect-gateway def1\nroute 0.0.0.0 0.0.0.0\n')
        self.assertNotIn('redirect-gateway',result); self.assertNotIn('route 0',result)
        self.assertIn('remote-cert-tls server',result)
    def test_managed_split_routing_directives_import(self):
        result=sanitize(BASE+'auth-user-pass\nroute-nopull\nroute-noexec\n')
        self.assertIn('auth-user-pass',result)
        self.assertNotIn('route-nopull',result)
        self.assertNotIn('route-noexec',result)
    def test_broad_ipv6_special_routes_rejected(self):
        for n in ['0.0.0.0/0','0.0.0.0/1','::/0','127.0.0.0/8','169.254.1.1/32','224.0.0.0/8','10.1.1.1/16']:
            with self.subTest(n=n), self.assertRaises(ValueError): network(n)
    def test_portable_privilege_drop(self):
        result=sanitize(BASE+'user nobody\ngroup nogroup\npersist-key\n')
        self.assertIn('user nobody',result)
        self.assertIn('group nobody',result)
        self.assertNotIn('nogroup',result)
        self.assertIn('persist-key',result)
        self.assertIn('group nobody',sanitize(BASE+'user nobody\n'))
        self.assertIn('user nobody',sanitize(BASE+'user openvpn\n'))
    def test_privileged_or_malformed_accounts_rejected(self):
        for option in ['user root','user 0','group wheel','group 0','user nobody extra','group nogroup extra']:
            with self.subTest(option=option),self.assertRaises(ValueError): sanitize(BASE+option)
    def test_common_export_noise_preserves_replay_protection(self):
        result=sanitize(BASE+'pull\nmute-replay-warnings\n')
        self.assertNotIn('mute-replay-warnings',result)
        self.assertNotIn('no-replay',result)
        with self.assertRaises(ValueError): sanitize(BASE+'pull unexpected\n')
    def test_aead_auth_none_keeps_authenticated_encryption(self):
        result=sanitize(BASE+'cipher AES-256-GCM\nauth none\n')
        self.assertIn('data-ciphers AES-256-GCM',result)
        for extra in ['cipher AES-256-CBC\nauth none', 'data-ciphers AES-256-GCM:AES-256-CBC\nauth none', 'cipher none', 'data-ciphers none', 'auth none\n<tls-auth>\nkey\n</tls-auth>']:
            with self.subTest(extra=extra),self.assertRaises(ValueError):sanitize(BASE+extra)
    def test_route_suggestions_skip_default_and_bypass_routes(self):
        text=BASE+'route 10.20.0.0 255.255.0.0\nroute 0.0.0.0 0.0.0.0\nroute 10.30.0.0 255.255.0.0 net_gateway\nroute 10.40.0.0 255.255.0.0 vpn_gateway\n'
        self.assertEqual(suggested_routes(text),['10.20.0.0/16','10.40.0.0/16'])
    def test_missing_destinations_fail_before_login(self):
        with self.assertRaisesRegex(ValueError,'Destination CIDR'):policy([],[],'')
        self.assertEqual(policy([],['*.example.org'],'')[1],['*.example.org'])
    def test_overlap(self):
        with self.assertRaises(ValueError): conflicts([network('10.1.0.0/16')],[network('10.0.0.0/8')])
        conflicts([network('10.1.0.0/16')],[network('10.2.0.0/16')])
    def test_domain_validation(self):
        for d in ['https://a.com','*example.com','a.com;whoami','-a.com']:
            with self.subTest(d=d),self.assertRaises(ValueError): policy([], [d], '10.1.0.53')
        self.assertEqual(policy([],['stage.example.org'],'')[0],[])
        self.assertEqual(str(policy([],['stage.example.org'],'10.1.0.53')[0][0]),'10.1.0.53/32')
if __name__=='__main__': unittest.main()


class ServerOverrideTests(unittest.TestCase):
    def test_override_preserves_tls_blocks_and_port(self):
        from core import override_server
        result=override_server(BASE+'auth-user-pass\n','198.51.100.7')
        self.assertIn('remote 198.51.100.7 1194',result)
        self.assertIn('<ca>\ncertificate\n</ca>',result)
        self.assertIn('remote-cert-tls server',result)
        for value in ['https://example.org','a\nup /tmp/script','::1','--config /tmp/x']:
            with self.assertRaises(ValueError):override_server(BASE,value)


class ConnectExportTests(unittest.TestCase):
    def test_redundant_empty_auth_is_removed_only_with_explicit_digest(self):
        result=sanitize(BASE+'auth\nauth SHA1\ncipher AES-256-CBC\n')
        self.assertNotIn('auth',result.splitlines())
        self.assertIn('auth SHA1',result)
        self.assertIn('AES-256-CBC',next(line for line in result.splitlines() if line.startswith('data-ciphers ')))
        with self.assertRaises(ValueError):sanitize(BASE+'auth\n')
