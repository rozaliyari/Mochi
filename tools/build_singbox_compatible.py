"""Build the requested VLESS/VMess feature subset without new-macOS Cronet."""
import os
import pathlib
import subprocess
import tarfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
CACHE=ROOT/'build'/'portable-inputs'


def build():
    source=CACHE/'sing-box-source'
    if not source.exists():
        with tarfile.open(CACHE/'sing-box-1.14.4-source.tar.gz') as archive:archive.extractall(source,filter='data')
    go=next((p for p in ('/opt/homebrew/opt/go@1.26/bin/go','/usr/local/opt/go@1.26/bin/go') if pathlib.Path(p).is_file()),None)
    if not go:raise RuntimeError('Install Go 1.26 on the build machine first')
    env=dict(os.environ,CGO_ENABLED='0',GOOS='darwin',GOARCH='arm64',MACOSX_DEPLOYMENT_TARGET='13.0',
             GOCACHE=str(ROOT/'build/go-cache'),GOMODCACHE=str(ROOT/'build/go-modules'))
    command=[go,'build','-trimpath','-buildvcs=false','-tags','with_gvisor,with_utls,with_quic',
             '-ldflags','-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.4',
             '-o',str(CACHE/'sing-box-compatible'),'./cmd/sing-box']
    subprocess.run(command,cwd=source/'sing-box-1.14.4',env=env,check=True)
    print('Built the compatible VLESS/VMess engine')


if __name__=='__main__':build()
