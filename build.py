"""
build.py : Build the framework

This file is part of EPControl.

Copyright (C) 2016  Jean-Baptiste Galet & Timothe Aeberhardt

EPControl is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

EPControl is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with EPControl.  If not, see <http://www.gnu.org/licenses/>.
"""
import sys
import os
import shutil
import argparse
import subprocess
import tempfile
from pathlib import Path
import tarfile
import uuid

import collections

from gitlab import GitlabUtils
from manifest import Manifest

try:
    import sh
    from sh import wget, tar, unzip, fpm, ErrorReturnCode
except:
    pass

PYTHON_VERSION = '3.5.2'
APPVEYOR_PYTHON = '35'

CWD = Path(os.path.dirname(os.path.realpath(__file__)))
BUILD_DIR = CWD / 'build'
DIST_DIR = CWD / 'dist'
TMP_DIR = BUILD_DIR / 'tmp'

YARADROID_ID = os.getenv("YARADROID_ID")

DOCKER_REGISTRY = os.getenv("DOCKER_REGISTRY")


def run_cmd(args):
    """Run a command"""
    with subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1) as proc:
        stdout, stderr = proc.communicate()
        print(stdout)
        return proc.returncode == 0


class Builder(object):
    def __init__(self, osname, arch):
        self.os = osname
        self.arch = arch
        self.requirements = []
        self.patched_requirements = []
        self.run_cmd = run_cmd
        self.CODE_PATH = str(TMP_DIR / 'lib' / 'python3.5' / 'site-packages')
        
    def build_manifest(self, signkey):
        print("Building manifest")
        configclass = collections.namedtuple('Config', ['CODE_PATH', 'BIN_PATH', 'MANIFEST_PRIVKEY'])
        manifest = Manifest(configclass(
            CODE_PATH=[self.CODE_PATH],
            BIN_PATH=str(DIST_DIR / '{}_{}'.format(self.os, self.arch)),
            MANIFEST_PRIVKEY=signkey
        ))
        manifest.build_manifest()
        print("Manifest built, writing...")
        manifest.write_bin()
        print("Manifest OK")

    def create_venv(self):
        raise NotImplementedError()

    def build(self):
        venv_py = self.create_venv()
        self.run_cmd([
            venv_py,
            '-m', 'pip',
            'install',
            '--upgrade',
            'wheel'
        ])

        for req in self.requirements:
            print("Install requirement: {}".format(req))
            if not self.run_cmd([
                venv_py,
                '-m', 'pip',
                'install',
                req
            ]):
                raise RuntimeError("Cannot install {}".format(req))

        for req in self.patched_requirements:
            os.makedirs(str(TMP_DIR / req))
            os.chdir(str(TMP_DIR / req))
            print("Install patched requirement: {}".format(req))
            if not self.run_cmd([
                venv_py,
                '-m', 'pip',
                'download',
                req
            ]):
                raise RuntimeError("Cannot download {}".format(req))
            arch_path = next((TMP_DIR / req).glob('*'))
            try:
                archive = tarfile.open(str(arch_path))
                archive.extractall()
            except tarfile.TarError:
                raise RuntimeError("Cannot untar {}".format(req))
            os.chdir(os.path.commonprefix(archive.getnames()))
            if not self.run_cmd([
                venv_py,
                str(CWD / 'patch.py'),
                str(CWD / 'patchs' / '{}_{}.patch'.format(req, self.os))
            ]):
                raise RuntimeError("Cannot patch {}".format(req))
            if not self.run_cmd([
                venv_py,
                '-m', 'pip',
                'install',
                '--upgrade',
                '.'
            ]):
                raise RuntimeError("Cannot install {}".format(req))

        print("Install EPCLib")
        os.chdir(str(CWD))
        if not self.run_cmd([
            venv_py,
            '-m', 'pip',
            'install',
            '.'
        ]):
            raise RuntimeError("Cannot install EPCLib")

        print("Build successful")


class WinBuilder(Builder):
    def __init__(self, arch):
        super(WinBuilder, self).__init__('win', arch)
        self.pyarch = 'win32' if arch == 'x86' else 'amd64'
        self.requirements.extend([
            'https://github.com/PokeSec/pefile/archive/master.zip',
            'yara-python',
            'defusedxml'])
        self.patched_requirements.append('pytsk3')

        global TMP_DIR
        TMP_DIR /= self.arch
        self.CODE_PATH = str(TMP_DIR / 'Lib' / 'site-packages')

        os.makedirs(str(BUILD_DIR), exist_ok=True)
        os.makedirs(str(TMP_DIR), exist_ok=True)
        os.makedirs(str(DIST_DIR / 'win_{}'.format(self.arch)), exist_ok=True)

        self.python_dir = Path('C:\\Python{}{}'.format(APPVEYOR_PYTHON, '-x64' if self.pyarch == 'amd64' else ''))

        # Python builds libeay as libeay.py but some libs require libeay32/64
        rawarch = '32' if self.arch == 'x86' else '64'
        tmp = self.python_dir / "Python-{}".format(PYTHON_VERSION) / 'PCbuild' / self.pyarch / 'libeay{}.lib'.format(rawarch)
        if not tmp.exists():
            shutil.copy(
                str(self.python_dir / "Python-{}".format(PYTHON_VERSION) / 'PCbuild' / self.pyarch / 'libeay.lib'),
                str(tmp))

    def create_venv(self):
        # Create venv
        if not self.run_cmd([
            str(self.python_dir / "Python-{}".format(PYTHON_VERSION) / 'python.bat'),
            '-m', 'venv',
            '--copies',
            '--clear',
            str(TMP_DIR)
        ]):
            raise RuntimeError("Cannot create venv")
        return str(TMP_DIR / 'Scripts' / 'python.exe')


class OSXBuilder(Builder):
    def __init__(self, arch):
        super(OSXBuilder, self).__init__('osx', arch)
        os.makedirs(str(BUILD_DIR), exist_ok=True)
        os.makedirs(str(BUILD_DIR / 'build'), exist_ok=True)
        os.makedirs(str(TMP_DIR), exist_ok=True)
        os.makedirs(str(DIST_DIR / 'osx_{}'.format(self.arch)), exist_ok=True)
        self.requirements.extend([
            'pytsk3',
            'https://github.com/PokeSec/pefile/archive/master.zip',
            'yara-python',
            'defusedxml'])
        self.build_python()

    def build_python(self):
        os.chdir(str(BUILD_DIR))
        print("Building Python {}".format(PYTHON_VERSION))
        print(tar(
            wget('-O-', 'https://www.python.org/ftp/python/{0}/Python-{0}.tar.xz'.format(PYTHON_VERSION)),
            "xJ", _err_to_out=True))
        os.chdir(str(BUILD_DIR / "Python-{}".format(PYTHON_VERSION)))
        print(sh.Command('./configure')(
            prefix=str(BUILD_DIR / 'python'),
            _env={
                "CFLAGS": "-I/usr/local/opt/openssl/include",
                "LDFLAGS": "-L/usr/local/opt/openssl/lib"
            },
            _err_to_out=True
        ))
        print(sh.Command('make')('-j4', _err_to_out=True))
        print(sh.Command('make')('install', _err_to_out=True))
        shutil.rmtree(str(BUILD_DIR / 'python' / 'lib' / 'python3.5' / 'test'))

    def create_venv(self):
        print(sh.Command(str(BUILD_DIR / 'python' / 'bin' / 'python3'))(
            '-m', 'venv',
            '--copies',
            '--clear',
            str(TMP_DIR)
        ))
        return str(TMP_DIR / 'bin' / 'python3')


class LinuxBuilder(Builder):
    def __init__(self, arch, osname):
        super(LinuxBuilder, self).__init__(osname, arch)
        self.requirements.extend(['pytsk3',
                                  'https://github.com/PokeSec/pefile/archive/master.zip',
                                  'yara-python',
                                  'distro',
                                  'defusedxml'])
        self.__setup_docker()
        self.run_cmd = self.__run_cmd_docker

    def __setup_docker(self):
        from sh import docker
        self.docker = docker
        self.docker_image = 'python-{}-{}'.format(self.os, self.arch)
        self.container_id = uuid.uuid4()
        try:
            print(self.docker.login('-u', 'gitlab-ci-token', '-p', os.environ['CI_BUILD_TOKEN'], DOCKER_REGISTRY))
        except KeyError:
            print("No CI_BUILD_TOKEN available, assuming docker is already logged in to the {} registry".format(
                DOCKER_REGISTRY))
        self.docker.run('-dit',
                        '-v',
                        "{}:/opt/build".format(CWD),
                        '-w',
                        '/opt/build',
                        '--name',
                        self.container_id,
                        self.docker_image)

        # Change global build dirs from docker
        global BUILD_DIR
        global DIST_DIR
        global TMP_DIR
        BUILD_DIR = Path('/opt/build/') / 'build'
        DIST_DIR = Path('/opt/build/') / 'dist'
        TMP_DIR = BUILD_DIR / 'tmp'
        self.docker.exec(self.container_id,
                         'mkdir', '-p',
                         str(BUILD_DIR))
        self.docker.exec(self.container_id,
                         'mkdir', '-p',
                         str(BUILD_DIR / 'build'))
        self.docker.exec(self.container_id,
                         'mkdir', '-p',
                         str(TMP_DIR))
        self.docker.exec(self.container_id,
                         'mkdir', '-p',
                         str(DIST_DIR / '{}_{}'.format(self.os, self.arch)))
        self.docker.exec(self.container_id,
                         'chmod',
                         '-R',
                         '777',
                         str(BUILD_DIR))
        self.docker.exec(self.container_id,
                         'chmod',
                         '-R',
                         '777',
                         str(DIST_DIR))

    def stop(self):
        print("Stopping the docker container...")
        self.docker.exec(self.container_id,
                         'rm',
                         '-rf',
                         '/opt/build/build')
        self.docker.stop(self.container_id)
        self.docker.rm(self.container_id)

    def __run_cmd_docker(self, args):
        try:
            self.docker.exec(self.container_id, *args)
            return True
        except Exception as exc:
            print("Error in docker command", exc)
            return False

    def create_venv(self):
        self.run_cmd(['/opt/python/python/bin/python3',
                      '-m', 'venv',
                      '--copies',
                      '--clear',
                      str(TMP_DIR)]
                      )
        return str(TMP_DIR / 'bin' / 'python3')

    def build_manifest(self, signkey):
        # Restore global dirs
        global BUILD_DIR
        global DIST_DIR
        global TMP_DIR
        BUILD_DIR = CWD / 'build'
        DIST_DIR = CWD / 'dist'
        TMP_DIR = BUILD_DIR / 'tmp'
        super(LinuxBuilder, self).build_manifest(signkey)


CRYSTAX_PATH = Path('/opt/android-build/crystax-ndk-10.3.2')
PYTHON_CRYSTAX_VERSION = '3.5'  # FIXME: use SemVer with https://pypi.python.org/pypi/semantic_version/ ?
OPENSSL_VERSION = '1.0.2i'
ABI = 'armeabi-v7a'
MARCH = 'armv7-a'
PLATFORM_NAME = 'arm'
API_LEVEL = 21
TOOLCHAIN = 'arm-linux-androideabi'
HOST_TAG = 'linux-x86_64'


class AndroidBuilder(Builder):
    def __init__(self, arch):
        super(AndroidBuilder, self).__init__('android', arch)
        self.dist_dir = str(DIST_DIR / 'android_{}'.format(arch))
        os.makedirs(str(BUILD_DIR), exist_ok=True)
        os.makedirs(str(BUILD_DIR / 'build'), exist_ok=True)
        os.makedirs(str(TMP_DIR), exist_ok=True)
        os.makedirs(self.dist_dir, exist_ok=True)
        self.__setup_env_variables()

    def __setup_env_variables(self):
        # Crystax
        crystax_bin = CRYSTAX_PATH / 'toolchains' / '{}-5'.format(TOOLCHAIN) / 'prebuilt' / HOST_TAG / 'bin'
        crystax_lib = CRYSTAX_PATH / 'sources' / 'crystax' / 'libs' / ABI
        sysroot = CRYSTAX_PATH / 'platforms' / 'android-{}'.format(API_LEVEL) / 'arch-{}'.format(PLATFORM_NAME)
        gcc = crystax_bin / '{}-gcc'.format(TOOLCHAIN)
        gpp = crystax_bin / '{}-g++'.format(TOOLCHAIN)

        # Python
        python_dir = CRYSTAX_PATH / 'sources' / 'python' / PYTHON_CRYSTAX_VERSION
        python_inc = python_dir / 'include' / 'python'
        python_lib = python_dir / 'libs' / ABI

        # OpenSSL
        openssl_dir = CRYSTAX_PATH / 'sources' / 'openssl' / OPENSSL_VERSION
        openssl_inc = openssl_dir / 'include'
        openssl_lib = openssl_dir / 'libs' / ABI

        # Set environment variables
        os.environ['CC'] = str(gcc)
        os.environ['CXX'] = str(gpp)
        os.environ['CFLAGS'] = os.environ['CXXFLAGS'] = "--sysroot {} -I{} -I{} -march={} " \
                                                        "-mfloat-abi=softfp -mfpu=vfp -mthumb".format(str(sysroot),
                                                                                                      python_inc,
                                                                                                      openssl_inc,
                                                                                                      MARCH)
        os.environ['LDFLAGS'] = "-lm -lcrystax -L{} -L{} -L{} -lcrypto".format(crystax_lib, python_lib, openssl_lib)
        os.environ['LDSHARED'] = '{} -DANDROID -mandroid -fomit-frame-pointer --sysroot {} -L{} -L{} -L{} ' \
                                 '-lm -lcrystax -lcrypto -lpython3.5m -shared'.format(gcc,
                                                                                      str(sysroot),
                                                                                      crystax_lib,
                                                                                      python_lib,
                                                                                      openssl_lib)

    def create_venv(self):
        print(sh.python3(
            '-m', 'venv',
            '--copies',
            '--clear',
            str(TMP_DIR)
        ))
        return str(TMP_DIR / 'bin' / 'python3')

    def fetch_yaradroid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpzip = os.path.join(tmpdir, "yaradroid.zip")
            artifacts = GitlabUtils.get_latest_artifact(YARADROID_ID, 'build')
            if artifacts:
                with open(tmpzip, 'wb') as ofile:
                    ofile.write(artifacts)
                print(sh.unzip('-o',
                               '-j',
                               tmpzip,
                               'app/build/intermediates/cmake/debug/obj/armeabi-v7a/yara.so',
                               '-d',
                               self.CODE_PATH))
            else:
                raise RuntimeError("Cannot download yaradroid")

def main():
    """Entry Point"""
    parser = argparse.ArgumentParser(description="Build the framework")
    parser.add_argument('os', choices=['win', 'linux', 'osx', 'android'],
                        help="The os for which to build the framework")
    parser.add_argument('arch', choices=['x86', 'x64', 'arm'], help="The arch for which to build the framework")
    parser.add_argument('--distro', choices=[
        'centos6',
        'centos7',
        'debian7',
        'debian8',
        'sles11',
        'sles12',
        'ubuntu12.04',
        'ubuntu14.04',
        'ubuntu16.04',
        'self',
        ], help="The linux distribution", required=False)
    parser.add_argument('signkey', type=argparse.FileType('r'), default=str(CWD / 'sign_priv.pem'))
    args = parser.parse_args()

    try:
        if args.os == 'win':
            builder = WinBuilder(args.arch)
            builder.build()
            builder.build_manifest(args.signkey)
        elif args.os == 'osx':
            builder = OSXBuilder(args.arch)
            builder.build()
            builder.build_manifest(args.signkey)
        elif args.os == 'android':
            environ = dict(os.environ)
            try:
                builder = AndroidBuilder(args.arch)
                builder.build()
                builder.fetch_yaradroid()
                builder.build_manifest(args.signkey)
            finally:
                os.environ.clear()
                os.environ.update(environ)
        else:
            if not DOCKER_REGISTRY:
                sys.exit("Please specify DOCKER_REGISTRY, environment variables")
            if not args.distro:
                sys.exit("Please specified a valid linux distribution")
            builder = LinuxBuilder(args.arch, args.distro)
            builder.build()
            builder.build_manifest(args.signkey)
            builder.stop()

    except RuntimeError as exc:
        sys.exit("BUILD ERROR : {}".format(exc))

if __name__ == '__main__':
    main()
