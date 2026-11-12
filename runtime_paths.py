"""Locate only packaged engines or the known development Homebrew locations."""
import os
import pathlib
import sys

PORTABLE_PYTHON='3.14'


def bundle_contents():
    candidate=pathlib.Path(__file__).resolve().parents[2]
    if candidate.name=='Contents' and (candidate/'MacOS'/'MochiRuntime').is_file():return candidate
    return None


def engine_paths(name):
    if name not in ('openvpn','sing-box'):raise ValueError('Unknown engine')
    contents=bundle_contents()
    if contents:return (str(contents/'Helpers'/name),)
    return ('/opt/homebrew/sbin/openvpn','/usr/local/sbin/openvpn') if name=='openvpn' else ('/opt/homebrew/bin/sing-box','/usr/local/bin/sing-box')


def runtime_environment():
    env=dict(os.environ)
    contents=bundle_contents()
    if contents:
        for key in tuple(env):
            if key.startswith(('PYTHON','DYLD_')) or key=='__PYVENV_LAUNCHER__':env.pop(key,None)
        env.update(PYTHONHOME=str(contents/'Frameworks'/'Python.framework'/'Versions'/PORTABLE_PYTHON),
                   PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1',
                   TCL_LIBRARY=str(contents/'Resources'/'Runtime'/'tcl'),
                   TK_LIBRARY=str(contents/'Resources'/'Runtime'/'tk'),
                   SSL_CERT_FILE=str(contents/'Resources'/'Runtime'/'cacert.pem'))
    return env


def python_command(script,*arguments):
    flags=['-B','-s','-S'] if bundle_contents() else []
    return [sys.executable,*flags,str(script),*map(str,arguments)]
