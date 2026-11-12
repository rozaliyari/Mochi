"""Per-user macOS Keychain storage via Security.framework (no shell/password argv)."""
import ctypes as C
import json
import re
import sys
import hashlib
import uuid
from contextlib import contextmanager

SERVICE='com.mochi.saved-logins'
# Successful reads stay in this process only; nothing is cached on disk.
_session_logins={}


class KeychainError(RuntimeError):
    pass


def checked_id(profile_id):
    if not isinstance(profile_id,str) or not re.fullmatch('[a-f0-9]{32}',profile_id):
        raise KeychainError('Invalid local credential identifier')
    return profile_id


def checked_login(data):
    if not isinstance(data,dict) or set(data)-{'username','password','key_password','mode','binding','otp_seed'}:
        raise KeychainError('Invalid saved login fields')
    result={key:data.get(key,'password' if key=='mode' else '') for key in ('username','password','key_password','mode','binding','otp_seed')}
    if result['binding'] and not re.fullmatch('[a-f0-9]{64}',result['binding']):raise KeychainError('Invalid VPN credential binding')
    if result['mode'] not in ('password','dynamic'):raise KeychainError('Invalid saved login mode')
    if result['otp_seed']:
        from auth import totp_secret
        try:totp_secret(result['otp_seed'])
        except ValueError:raise KeychainError('Invalid saved Authenticator key') from None
    for key,value in result.items():
        if not isinstance(value,str) or len(value)>1024 or any(c in value for c in '\0\r\n'):
            raise KeychainError('Invalid saved login details')
    return result


class NativeKeychain:
    def __init__(self):
        if sys.platform!='darwin':raise KeychainError('Password storage requires macOS Keychain')
        self.cf=C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sec=C.CDLL('/System/Library/Frameworks/Security.framework/Security')
        self.cf.CFStringCreateWithCString.argtypes=[C.c_void_p,C.c_char_p,C.c_uint32];self.cf.CFStringCreateWithCString.restype=C.c_void_p
        self.cf.CFDataCreate.argtypes=[C.c_void_p,C.c_void_p,C.c_long];self.cf.CFDataCreate.restype=C.c_void_p
        self.cf.CFDictionaryCreateMutable.argtypes=[C.c_void_p,C.c_long,C.c_void_p,C.c_void_p];self.cf.CFDictionaryCreateMutable.restype=C.c_void_p
        self.cf.CFDictionarySetValue.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p]
        self.cf.CFRelease.argtypes=[C.c_void_p]
        self.cf.CFGetTypeID.argtypes=[C.c_void_p];self.cf.CFGetTypeID.restype=C.c_ulong
        self.cf.CFDataGetTypeID.restype=C.c_ulong
        self.cf.CFDataGetLength.argtypes=[C.c_void_p];self.cf.CFDataGetLength.restype=C.c_long
        self.cf.CFDataGetBytePtr.argtypes=[C.c_void_p];self.cf.CFDataGetBytePtr.restype=C.c_void_p
        for name,args in [('SecItemAdd',[C.c_void_p,C.c_void_p]),('SecItemUpdate',[C.c_void_p,C.c_void_p]),('SecItemDelete',[C.c_void_p]),('SecItemCopyMatching',[C.c_void_p,C.POINTER(C.c_void_p)])]:
            function=getattr(self.sec,name);function.argtypes=args;function.restype=C.c_int32

    def constant(self,name):
        return C.c_void_p.in_dll(self.cf if name.startswith('kCF') else self.sec,name).value

    @contextmanager
    def dictionary(self,account=None,payload=None,reading=False):
        objects=[]
        dictionary=self.cf.CFDictionaryCreateMutable(None,0,None,None)
        if not dictionary:raise KeychainError('Cannot allocate Keychain request')
        def string(value):
            obj=self.cf.CFStringCreateWithCString(None,value.encode(),0x08000100)
            if not obj:raise KeychainError('Cannot encode Keychain request')
            objects.append(obj);return obj
        def put(key,value):self.cf.CFDictionarySetValue(dictionary,self.constant(key),value)
        try:
            if account is not None:
                put('kSecClass',self.constant('kSecClassGenericPassword'))
                put('kSecAttrService',string(SERVICE))
                put('kSecAttrAccount',string(account))
            if payload is not None:
                buffer=C.create_string_buffer(payload)
                obj=self.cf.CFDataCreate(None,buffer,len(payload))
                if not obj:raise KeychainError('Cannot encode saved passwords')
                objects.append(obj);put('kSecValueData',obj)
            if reading:
                put('kSecReturnData',self.constant('kCFBooleanTrue'))
                put('kSecMatchLimit',self.constant('kSecMatchLimitOne'))
            yield dictionary
        finally:
            self.cf.CFRelease(dictionary)
            for obj in objects:self.cf.CFRelease(obj)

    def check(self,status):
        if status:
            if status in (-128,-25293,-25308):
                raise KeychainError('Keychain access was cancelled, denied or locked. Unlock the login Keychain and try again.')
            raise KeychainError(f'macOS could not access the saved login (status {status})')

    def read(self,account):
        result=C.c_void_p()
        with self.dictionary(account,reading=True) as query:
            status=self.sec.SecItemCopyMatching(query,C.byref(result))
        if status==-25300:return None
        self.check(status)
        try:
            if not result.value or self.cf.CFGetTypeID(result)!=self.cf.CFDataGetTypeID():
                raise KeychainError('Invalid Keychain result')
            length=self.cf.CFDataGetLength(result)
            if not 0<=length<=16384:raise KeychainError('Saved login is too large')
            return C.string_at(self.cf.CFDataGetBytePtr(result),length)
        finally:
            if result.value:self.cf.CFRelease(result)

    def write(self,account,payload):
        with self.dictionary(account) as query,self.dictionary(payload=payload) as update:
            status=self.sec.SecItemUpdate(query,update)
        if status==-25300:
            with self.dictionary(account,payload=payload) as item:status=self.sec.SecItemAdd(item,None)
        self.check(status)

    def delete(self,account):
        with self.dictionary(account) as query:status=self.sec.SecItemDelete(query)
        if status!=-25300:self.check(status)


def load(profile_id,backend=None):
    account=checked_id(profile_id)
    if backend is None and account in _session_logins:return dict(_session_logins[account])
    payload=(backend or NativeKeychain()).read(account)
    if payload is None:return None
    try:login=checked_login(json.loads(payload.decode()))
    except (UnicodeError,ValueError,TypeError) as e:raise KeychainError('Saved login is invalid') from e
    if backend is None:_session_logins[account]=dict(login)
    return login


def save(profile_id,data,backend=None):
    account=checked_id(profile_id)
    login=checked_login(data)
    payload=json.dumps(login,ensure_ascii=False).encode()
    if backend is None:_session_logins.pop(account,None)
    (backend or NativeKeychain()).write(account,payload)
    if backend is None:_session_logins[account]=dict(login)


def delete(profile_id,backend=None):
    account=checked_id(profile_id)
    if backend is None:_session_logins.pop(account,None)
    (backend or NativeKeychain()).delete(account)


def profile_id(name,settings_path):
    return uuid.uuid5(uuid.NAMESPACE_URL,SERVICE+':'+str(settings_path.resolve())+':'+name).hex


def binding(profile):
    return hashlib.sha256(profile.encode()).hexdigest()
