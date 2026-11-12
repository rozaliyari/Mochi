import json,unittest
import keychain
from unittest.mock import patch,Mock

class MemoryKeychain:
    def __init__(self):self.items={}
    def read(self,account):return self.items.get(account)
    def write(self,account,payload):self.items[account]=payload
    def delete(self,account):self.items.pop(account,None)

class KeychainTests(unittest.TestCase):
    def test_native_session_reads_once_and_forget_invalidates(self):
        keychain._session_logins.clear()
        backend=MemoryKeychain()
        account='b'*32
        backend.items[account]=json.dumps(dict(username='alice',password='dummy')).encode()
        read=Mock(wraps=backend.read);backend.read=read
        with patch.object(keychain,'NativeKeychain',return_value=backend):
            first=keychain.load(account);first['password']='caller mutation'
            self.assertEqual(keychain.load(account)['password'],'dummy')
            self.assertEqual(read.call_count,1)
            keychain.save(account,dict(username='alice',password='updated-dummy'))
            self.assertEqual(keychain.load(account)['password'],'updated-dummy')
            self.assertEqual(read.call_count,1)
            keychain.delete(account)
            self.assertIsNone(keychain.load(account))
        keychain._session_logins.clear()
    def setUp(self):self.backend=MemoryKeychain();self.account='a'*32
    def test_fixed_password_and_private_key_round_trip_and_delete(self):
        data=dict(username='alice',password='dummy-only',key_password='dummy-key',mode='password',binding=keychain.binding('config'))
        keychain.save(self.account,data,self.backend)
        self.assertEqual(keychain.load(self.account,self.backend),dict(data,otp_seed=''))
        keychain.delete(self.account,self.backend)
        self.assertIsNone(keychain.load(self.account,self.backend))
    def test_code_and_seed_are_never_accepted_as_fields(self):
        for field in ('otp','phone_code','seed','totp_secret'):
            with self.subTest(field=field),self.assertRaises(keychain.KeychainError):
                keychain.save(self.account,{field:'dummy-only'},self.backend)
        self.assertEqual(self.backend.items,{})
    def test_profile_changes_change_binding(self):
        self.assertNotEqual(keychain.binding('remote one'),keychain.binding('remote two'))
        with self.assertRaises(keychain.KeychainError):keychain.save('../account',{},self.backend)
    def test_corrupted_payload_fails_without_exposing_its_data(self):
        self.backend.items[self.account]=b'{invalid sensitive data'
        with self.assertRaisesRegex(keychain.KeychainError,'Saved login is invalid'):
            keychain.load(self.account,self.backend)
