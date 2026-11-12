import unittest
from server_profile import build_profile

CA='-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----'
class ServerProfileTests(unittest.TestCase):
    def test_profile_requires_trusted_ca_and_produces_no_default_route(self):
        p=build_profile('vpn.example.com','443','tcp-client',CA)
        self.assertIn('remote vpn.example.com 443',p)
        self.assertIn('remote-cert-tls server',p)
        self.assertIn('auth-user-pass',p)
        self.assertNotIn('redirect-gateway',p)
        self.assertNotIn('password',p)
    def test_rejects_injection_missing_ca_and_partial_client_identity(self):
        cases=[dict(host='x\nup script'),dict(host='https://example.com'),dict(port=0),dict(proto='tap'),dict(ca=''),dict(ca=CA+'\n</ca>\nup script'),dict(cert=CA)]
        for override in cases:
            args=dict(host='198.51.100.2',port=1194,proto='udp',ca=CA)
            args.update(override)
            with self.subTest(override=override),self.assertRaises(ValueError):build_profile(**args)
