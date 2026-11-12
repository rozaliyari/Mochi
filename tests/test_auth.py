import pathlib,tempfile,unittest
from unittest.mock import Mock,patch
import helper
from auth import credentials,totp,totp_secret
from core import sanitize
from test_core import BASE

class AuthTests(unittest.TestCase):
    def test_password_and_two_step_payloads(self):
        self.assertEqual(credentials('alice','secret'),('alice','secret'))
        self.assertEqual(credentials('alice','','dynamic'),('alice',''))
    def test_credentials_cannot_inject_extra_lines(self):
        for username,password in [('a\nb','secret'),('alice','pass\nextra'),('alice',''),('alice','p\x00s')]:
            with self.assertRaises(ValueError): credentials(username,password)
    def test_profile_auth_and_static_challenge(self):
        self.assertIn('auth-user-pass',sanitize(BASE+'auth-user-pass\n'))
        with self.assertRaises(ValueError): sanitize(BASE+'auth-user-pass /tmp/secret\n')
        self.assertIn('static-challenge',sanitize(BASE+'static-challenge "Enter code" 0\n'))
    def test_rfc6238_sha1_vector_truncated_to_six_digits(self):
        key='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        self.assertEqual(totp(key,59),'287082')
        self.assertEqual(totp(key,1111111109),'081804')
        self.assertEqual(totp(key,2000000000),'279037')
        self.assertEqual(totp(key.lower(),59),'287082')
        with self.assertRaises(ValueError): totp_secret('not a private key!')
    def test_helper_uses_private_management_not_password_files(self):
        helper.SESSIONS.clear()
        with tempfile.TemporaryDirectory() as d,patch.object(helper,'ROOT',d),patch.object(helper,'BINARY','/fake/openvpn',create=True),patch.object(helper.subprocess,'Popen',return_value=Mock()) as popen,patch.object(helper.threading,'Thread'),patch.object(helper,'remove_routes'):
            helper.dispatch(dict(op='connect',name='test',profile=BASE+'auth-user-pass\n',cidrs=['10.20.0.0/16'],credentials={'username':'alice','password':'secret'}))
            s=helper.SESSIONS['test']; args=popen.call_args.args[0]
            self.assertIn('--management-query-passwords',args)
            self.assertIn('unix',args)
            self.assertNotIn('secret',args)
            files=list(pathlib.Path(d).rglob('*'))
            self.assertFalse(any(p.name=='credentials' for p in files))
            self.assertFalse(any(p.is_file() and 'secret' in p.read_text() for p in files))
            helper.disconnect(s)
            self.assertIsNone(s['bridge'].initial)
        helper.SESSIONS.clear()

class PhoneCodeTests(unittest.TestCase):
    def test_persian_digits_whitespace_and_leading_zero(self):
        from auth import phone_code
        self.assertEqual(phone_code(' ۰۱۲ ۳۴۵\n'),'012345')
        self.assertEqual(phone_code('٠١٢٣٤٥'),'012345')
