"""Credential validation, without persistence or logging of submitted values."""
def value(text, label):
    if not isinstance(text,str) or not text or len(text)>1024 or any(c in text for c in '\r\n\x00'):
        raise ValueError(label+' is required and must be a single line (maximum 1024 characters)')
    return text

def credentials(username,password,mode='password',otp='',otp_format=''):
    username=value(username,'Username')
    if mode=='password': return username,value(password,'Password')
    if mode=='dynamic':
        if password=='': return username,''
        return username,value(password,'Password')
    if mode!='otp': raise ValueError('Unsupported authentication mode')
    otp=value(otp,'One-time code')
    if otp_format=='code-only': return username,otp
    if otp_format=='password+code': return username,value(value(password,'Password')+otp,'Combined password')
    raise ValueError('Select the format required by your VPN server')

def totp_secret(text):
    import base64, re
    if not isinstance(text,str): raise ValueError('Enter the Authenticator setup key')
    text=re.sub(r'[\s-]','',text).upper().rstrip('=')
    if not re.fullmatch('[A-Z2-7]{16,256}',text): raise ValueError('Authenticator key must be a Base32 setup key, not a VPN private key')
    try: result=base64.b32decode(text+'='*((-len(text))%8))
    except Exception: raise ValueError('Invalid Authenticator setup key') from None
    return result

def totp_qr(uri):
    from urllib.parse import urlsplit, parse_qs
    parsed=urlsplit(uri)
    if parsed.scheme!='otpauth' or parsed.netloc!='totp':raise ValueError('Select an Authenticator TOTP QR image')
    values=parse_qs(parsed.query,strict_parsing=True)
    if values.get('algorithm',['SHA1'])!=['SHA1'] or values.get('digits',['6'])!=['6'] or values.get('period',['30'])!=['30']:
        raise ValueError('This QR uses a TOTP format that Mochi does not support')
    secret=values.get('secret',[''])[0].upper().replace(' ','')
    totp_secret(secret)
    return secret

def totp(secret,at=None):
    import hashlib,hmac,struct,time
    now=time.time() if at is None else at
    digest=hmac.new(totp_secret(secret),struct.pack('>Q',int(now)//30),hashlib.sha1).digest()
    offset=digest[-1]&15
    return f'{(int.from_bytes(digest[offset:offset+4],"big")&0x7fffffff)%1000000:06d}'


def phone_code(text):
    """Preserve leading zeroes and translate copied Persian/Arabic decimal digits."""
    import unicodedata
    text=text.strip()
    compact=''.join(c for c in text if not c.isspace())
    if compact and all(c.isdecimal() for c in compact):
        text=''.join(str(unicodedata.decimal(c)) for c in compact)
    return value(text,'One-time code')
