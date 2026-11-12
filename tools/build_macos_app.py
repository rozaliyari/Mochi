"""Build a local, ad-hoc-signed macOS app. No private profiles are bundled."""
import pathlib
import plistlib
import shutil
import subprocess
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from settings import VERSION


def build(destination):
    destination=pathlib.Path(destination).resolve()
    if destination.exists():raise ValueError('Choose a new output directory; existing app will not be overwritten')
    contents=destination/'Contents'
    executable=contents/'MacOS'/'Mochi'
    resources=contents/'Resources'/'Mochi'
    executable.parent.mkdir(parents=True)
    resources.mkdir(parents=True)
    for path in ROOT.glob('*.py'):shutil.copy2(path,resources/path.name)
    shutil.copytree(ROOT/'docs',resources/'docs')
    shutil.copy2(ROOT/'README.md',resources/'README.md')
    for name in ('Mochi.icns','mochi-status.png'):
        shutil.copy2(ROOT/'assets'/name,resources.parent/name)
    info=dict(CFBundleName='Mochi',CFBundleDisplayName='Mochi',CFBundleIdentifier='local.mochi.dashboard',
              CFBundleExecutable='Mochi',CFBundlePackageType='APPL',CFBundleShortVersionString=VERSION,
              CFBundleVersion=VERSION,CFBundleIconFile='Mochi.icns',LSMinimumSystemVersion='13.0',NSHighResolutionCapable=True,
              NSHumanReadableCopyright='Mochi — local desktop VPN dashboard')
    with (contents/'Info.plist').open('wb') as stream:plistlib.dump(info,stream)
    subprocess.run(['/usr/bin/clang','-O2','-fobjc-arc','-fno-modules','-mmacosx-version-min=13.0','-framework','AppKit','-framework','Foundation',str(ROOT/'native'/'Launcher.m'),'-o',str(executable)],check=True)
    subprocess.run(['/usr/bin/codesign','--force','--deep','--sign','-',str(destination)],check=True)
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(destination)],check=True)
    print('Built and verified '+str(destination))


if __name__=='__main__':build(sys.argv[1] if len(sys.argv)>1 else ROOT/'build'/'Mochi.app')
