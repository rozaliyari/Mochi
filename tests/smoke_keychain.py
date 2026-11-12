"""Optional macOS Keychain CRUD test; creates/deletes only its random dummy item."""
import pathlib,sys,uuid
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import keychain
account=uuid.uuid4().hex
payload=dict(username='test-only',password='dummy-only',key_password='dummy-key',mode='password',binding=keychain.binding('test-only-profile'))
try:
    keychain.save(account,payload)
    assert keychain.load(account)==payload
    payload['password']='dummy-updated';keychain.save(account,payload)
    assert keychain.load(account)==payload
finally:keychain.delete(account)
assert keychain.load(account) is None
print('Native macOS Keychain add/read/update/delete passed; dummy item removed')
