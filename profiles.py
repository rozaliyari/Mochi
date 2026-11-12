"""Private local preferences. Exported source never includes these files."""
import json
import os
import pathlib
import tempfile
from settings import MAX_PROFILES, MIN_PROFILES

FIELDS = dict(name='', path='', cidrs='', domains='', dns='', username='',
              auth_mode='password', server_override='', credential_id='', remember='0', engine='openvpn', server_label='')


class PreferencesError(ValueError):
    pass


def new_profile(existing=()):
    names=set(existing)
    for i in range(1, MAX_PROFILES + 2):
        name=f'vpn-{i}'
        if name not in names:return dict(FIELDS,name=name)
    raise PreferencesError('Cannot choose a unique VPN name')


DEFAULTS = [new_profile()]


def normalize(data,path=None):
    if not isinstance(data,list) or not MIN_PROFILES<=len(data)<=MAX_PROFILES:
        raise PreferencesError(f'Settings must contain {MIN_PROFILES}–{MAX_PROFILES} VPNs')
    result=[]
    for i,row in enumerate(data):
        if not isinstance(row,dict):raise PreferencesError('A VPN settings entry is invalid')
        base=dict(FIELDS,name=f'vpn-{i+1}')
        entry={key:str(row.get(key,default)) for key,default in base.items()}
        import keychain
        try:keychain.checked_id(entry['credential_id'])
        except keychain.KeychainError:entry['credential_id']=keychain.profile_id(entry['name'],path or pathlib.Path('profiles.json'))
        result.append(entry)
    return result


def load(path):
    path=pathlib.Path(path)
    try:text=path.read_text()
    except FileNotFoundError:return normalize([dict(x) for x in DEFAULTS],path)
    except OSError as e:raise PreferencesError('Cannot read local settings: '+str(e)) from e
    try:return normalize(json.loads(text),path)
    except (ValueError,TypeError) as e:
        raise PreferencesError('Local VPN settings are invalid; the file has been left unchanged. '+str(e)) from e


def save(path,data):
    path=pathlib.Path(path)
    if isinstance(data,list):data=normalize(data,path)
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:json.dump(data,f,indent=2)
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)
