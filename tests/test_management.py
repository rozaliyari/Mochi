import threading,unittest
from unittest.mock import Mock
from management import Bridge,dynamic_challenge,dynamic_password,quote

class ManagementTests(unittest.TestCase):
    def bridge(self):
        state={'state':'connecting','challenge':None}
        bridge=Bridge('/unused',state,threading.RLock(),('alice','password'))
        bridge.sock=Mock()
        return bridge,state
    def test_initial_credentials_and_dynamic_second_step(self):
        b,s=self.bridge()
        b.event(">PASSWORD:Need 'Auth' username/password")
        self.assertIn(b'password "Auth" "password"',b.sock.sendall.call_args.args[0])
        self.assertIsNone(b.initial)
        b.event(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R:opaque-state:YWxpY2U=:Enter OTP']")
        b.event(">PASSWORD:Need 'Auth' username/password")
        self.assertEqual(s['challenge']['text'],'Enter OTP')
        self.assertNotIn('password',s['challenge'])
        b.respond(s['challenge']['id'],'123456')
        self.assertIn(b'password "Auth" "CRV1::opaque-state::123456"',b.sock.sendall.call_args.args[0])
        self.assertIsNone(s['challenge'])
    def test_static_challenge_encodes_both_password_and_code(self):
        b,s=self.bridge()
        b.event(">PASSWORD:Need 'Auth' username/password SC:0,Enter OTP")
        b.respond(s['challenge']['id'],'123456')
        self.assertIn(b'SCRV1:cGFzc3dvcmQ=:MTIzNDU2',b.sock.sendall.call_args.args[0])
    def test_stale_challenge_and_bad_login_fail(self):
        b,s=self.bridge()
        with self.assertRaises(ValueError): b.respond('expired','123456')
        with self.assertRaises(ValueError): b.event(">PASSWORD:Verification Failed: 'Auth'")
    def test_management_escaping_and_response_injection(self):
        self.assertEqual(quote('a"b\\c'),'"a\\"b\\\\c"')
        with self.assertRaises(ValueError): quote('a\nkill')
        challenge=dynamic_challenge(">PASSWORD:Verification Failed: ['CRV1:R:s:YWxpY2U=:Enter OTP']")
        with self.assertRaises(ValueError): dynamic_password(challenge,'1\nsignal SIGTERM')
    def test_reconnect_after_connection_fails(self):
        b,s=self.bridge();s['state']='connected'
        with self.assertRaises(ValueError): b.event('>STATE:123,RECONNECTING,auth-failure,,,,')
    def test_private_key_prompt_is_separate(self):
        b,s=self.bridge()
        b.event(">PASSWORD:Need 'Private Key' password")
        self.assertEqual(s['challenge']['kind'],'private-key')
        b.respond(s['challenge']['id'],'dummy-key-pass')
        self.assertEqual(b.sock.sendall.call_args.args[0],b'password "Private Key" "dummy-key-pass"\n')
        self.assertIsNotNone(b.initial)
        self.assertIsNone(s['challenge'])
    def test_token_only_login(self):
        b,s=self.bridge();b.initial=('alice','')
        b.event(">PASSWORD:Need 'Auth' username/password")
        self.assertEqual(s['challenge']['kind'],'login-token')
        b.respond(s['challenge']['id'],'123456')
        self.assertIn(b'password "Auth" "123456"',b.sock.sendall.call_args.args[0])
        self.assertIsNone(b.initial)
    def test_private_key_failure_message(self):
        b,s=self.bridge()
        with self.assertRaisesRegex(ValueError,'private key password was rejected'):
            b.event(">PASSWORD:Verification Failed: 'Private Key'")

    def test_precollected_key_unlocks_without_delaying_fresh_token(self):
        b,s=self.bridge();b.initial=('alice','');b.key_password='dummy-key-pass'
        b.event(">PASSWORD:Need 'Auth' username/password")
        b.respond(s['challenge']['id'],'123456')
        b.event(">PASSWORD:Need 'Private Key' password")
        self.assertEqual(b.sock.sendall.call_args.args[0],b'password "Private Key" "dummy-key-pass"\n')
        self.assertIsNone(s['challenge'])
        self.assertEqual(b.key_password,'')

    def test_connected_state_does_not_depend_on_muted_log_messages(self):
        b,s=self.bridge()
        b.event('>STATE:123,ASSIGN_IP,,10.8.0.2,,,,')
        b.event('>STATE:124,CONNECTED,SUCCESS,10.8.0.2,198.51.100.2,1194,,,')
        self.assertEqual(s['local_ip'],'10.8.0.2')
        self.assertEqual(s['remote_ip'],'198.51.100.2')
        self.assertTrue(s['vpn_ready'])

    def test_dummy_encrypted_key_then_phone_code(self):
        b,s=self.bridge();b.initial=('alice','');b.key_password='dummy-access-key'
        b.event(">PASSWORD:Need 'Private Key' password")
        self.assertEqual(b.sock.sendall.call_args.args[0],b'password "Private Key" "dummy-access-key"\n')
        b.event(">PASSWORD:Need 'Auth' username/password")
        self.assertEqual(s['challenge']['kind'],'login-token')
        b.respond(s['challenge']['id'],'012345')
        self.assertEqual(b.sock.sendall.call_args.args[0],b'username "Auth" "alice"\npassword "Auth" "012345"\n')
        self.assertEqual(b.key_password,'')
