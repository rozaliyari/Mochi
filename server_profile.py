"""Build a self-contained TLS OpenVPN profile from explicit server settings."""
import ipaddress
import re
from core import sanitize


def build_profile(host, port, proto, ca, cert='', key=''):
    host=host.strip()
    try:
        address=ipaddress.ip_address(host)
        if address.version!=4: raise ValueError('This build supports IPv4 servers')
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?',host):
            raise ValueError('Enter a server IPv4 or hostname without a URL, spaces or paths')
    try:port=int(port)
    except (TypeError,ValueError): raise ValueError('Port must be a number') from None
    if not 1<=port<=65535:raise ValueError('Port must be between 1 and 65535')
    if proto not in ('udp','tcp-client'):raise ValueError('Choose UDP or TCP')
    if bool(cert.strip())!=bool(key.strip()):raise ValueError('Client certificate and private key must be provided together')
    def block(name,text,marker):
        if marker not in text or '<' in text or '>' in text or '\0' in text:
            raise ValueError('Provide valid PEM '+name+' material')
        return '<'+name+'>\n'+text.strip()+'\n</'+name+'>\n'
    profile=f'client\ndev tun\nproto {proto}\nremote {host} {port}\nnobind\nauth-user-pass\nremote-cert-tls server\n'
    profile+=block('ca',ca,'-----BEGIN CERTIFICATE-----')
    if cert.strip():
        profile+=block('cert',cert,'-----BEGIN CERTIFICATE-----')
        profile+=block('key',key,'PRIVATE KEY-----')
    return sanitize(profile)
