"""Download only official, pinned public inputs for the portable macOS build."""
import concurrent.futures
import hashlib
import base64
import json
import pathlib
import urllib.request

ROOT=pathlib.Path(__file__).resolve().parents[1]
CACHE=ROOT/'build'/'portable-inputs'
PYTHON_URL='https://www.python.org/ftp/python/3.14.10/python-3.14.10-macos11.pkg'
PYTHON_SHA='286c7018aa2730f6747ca433dccdc2b31be45f078a9ea0ffa44d5f06368fd2d7'
CA_COMMIT='ca446ca404ff3b962a0193f36e03d1eabb231968'
TUNNELBLICK_SOURCE_SHA='6e3e6ba37578a8cabb626f0b2b2bfda10db3d54712ccda6121399c426c748e61'


def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'Mochi-build'}),timeout=30) as response:
        return json.load(response)


def download(url,name,sha=None):
    CACHE.mkdir(parents=True,exist_ok=True)
    path=CACHE/name
    if path.exists() and (sha is None or hashlib.sha256(path.read_bytes()).hexdigest()==sha):return path
    temporary=path.with_suffix(path.suffix+'.partial')
    request=urllib.request.Request(url,headers={'User-Agent':'Mochi-build'})
    total=0;digest=hashlib.sha256()
    with urllib.request.urlopen(request,timeout=45) as response,temporary.open('wb') as stream:
        while chunk:=response.read(1024*1024):
            total+=len(chunk)
            if total>250_000_000:raise RuntimeError('Official input exceeds build download limit')
            stream.write(chunk);digest.update(chunk)
    if sha and digest.hexdigest()!=sha:
        temporary.unlink();raise RuntimeError('Checksum mismatch: '+name)
    temporary.replace(path)
    print('Downloaded',name,total,'bytes',flush=True)
    return path


def python_input():
    return download(PYTHON_URL,'python-3.14.10.pkg',PYTHON_SHA)


def singbox_input():
    data=get_json('https://api.github.com/repos/SagerNet/sing-box/releases/tags/v1.14.4')
    asset=next(a for a in data['assets'] if a['name']=='sing-box-1.14.4-darwin-arm64.tar.gz')
    digest=asset.get('digest','')
    if not digest.startswith('sha256:'):raise RuntimeError('Release asset does not supply a SHA-256 digest')
    return download(asset['browser_download_url'],asset['name'],digest.split(':',1)[1])


def source_inputs():
    data=get_json('https://api.github.com/repos/Tunnelblick/Tunnelblick/releases/tags/v10.0.2')
    (CACHE/'tunnelblick-release.json').write_text(json.dumps(data,indent=2))
    print('Tunnelblick release source metadata downloaded',flush=True)
    download('https://github.com/SagerNet/sing-box/archive/refs/tags/v1.14.4.tar.gz','sing-box-1.14.4-source.tar.gz','0958ccd23b1ea9a141d715d15478b1e040fd04bcca19d8ff5529636b1b753e18')
    download('https://github.com/Tunnelblick/Tunnelblick/archive/refs/tags/v10.0.2.tar.gz','tunnelblick-10.0.2-source.tar.gz',TUNNELBLICK_SOURCE_SHA)


def ca_input():
    for remote,local in [('certifi/cacert.pem','cacert.pem'),('LICENSE','certifi-LICENSE.txt')]:
        data=get_json('https://api.github.com/repos/certifi/python-certifi/contents/'+remote+'?ref='+CA_COMMIT)
        raw=base64.b64decode(data['content'])
        if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=data['sha']:
            raise RuntimeError('CA source blob checksum mismatch')
        (CACHE/local).write_bytes(raw)
    (CACHE/'ca-source.json').write_text(json.dumps(dict(repository='https://github.com/certifi/python-certifi',commit=CA_COMMIT),indent=2))


if __name__=='__main__':
    CACHE.mkdir(parents=True,exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(lambda function:function(),(python_input,singbox_input,source_inputs,ca_input)):pass
