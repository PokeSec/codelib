"""
manifest.py : Web manifest management

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
import binascii
import marshal
import re
import struct
from Crypto import Random
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import arrow
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

EXCLUDE_FROM_LIBRARY = [
    '.*__pycache__.*',
    'pip',
    'setuptools',
    'wheel',
    'pkg_resources',
    'easy_install.py',
    '.*egg-info.*',
    '.*dist-info.*'
]

FLAG_PKG = 1
FLAG_BIN = 2
FLAG_NOCACHE = 4


def unpack(stream, fmt):
    """
    Simple helper to unpack data from a stream
    """
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    return struct.unpack(fmt, buf)


class Module(object):
    """Code module"""

    def __init__(self, mod_hash, flags, mod_key, mod_code_hash):
        self.mod_hash = mod_hash
        self.is_pkg = True if flags & FLAG_PKG else False
        self.is_bin = True if flags & FLAG_BIN else False
        self.no_cache = True if flags & FLAG_NOCACHE else False
        self.__key = mod_key
        self.__hash = mod_code_hash
        self.__data = b''

    @classmethod
    def from_data(cls, data):
        """Initialize a Module from binary data"""
        try:
            items = unpack(data, '<32sB32s32s')
            mod_hash = items[0]
            flags = items[1]
            mod_key = items[2]
            mod_code_hash = items[3]
            return cls(mod_hash, flags, mod_key, mod_code_hash)
        except struct.error:
            return None

    def to_dict(self):
        """Get a dict from the module object"""
        info = {
            'is_pkg': self.is_pkg,
            'is_bin': self.is_bin,
            'no_cache': self.no_cache,
            'mod_hash': binascii.hexlify(self.mod_hash)
        }

        return info


class Manifest(object):
    """Manage code manifest"""

    def __init__(self, config):
        self.manifest = dict()
        self.config = config
        self.__code_path = [Path(x) for x in self.config.CODE_PATH]
        self.__extra_path = self.__code_path
        self.__data = b''
        self.__timestamp = 0

    def __get_extra_paths(self):
        """Parse pth files for extra paths"""
        for code_path in self.__code_path:
            for item in code_path.glob('**/*.pth'):
                with item.open() as ifile:
                    for line in ifile.readlines():
                        line = line.strip()
                        self.__extra_path.append(code_path.joinpath(Path(line)))

    def __get_best_relative(self, item):
        relitem = item
        for path in self.__extra_path:
            try:
                relitem = item.relative_to(path)
            except ValueError:
                pass
        return relitem

    def __write_output(self, data, filename):
        outpath = Path(self.config.BIN_PATH, filename)
        outpath.write_bytes(data)

    def write_bin(self):
        """Write the manifest to disk, in binary form"""
        infos = {}
        bin_path = Path(self.config.BIN_PATH, 'manifest.bin')

        header = b''
        header += struct.pack('<B', 1)  # version
        header += struct.pack('<B', 1)  # signature_type
        header += struct.pack('<H', len(self.manifest))  # mod_count
        header += struct.pack('<Q', arrow.utcnow().timestamp)  # timestamp

        body = b''
        for module, attr in self.manifest.items():
            name_hash = sha256(module.encode('ascii'))
            infos[module] = name_hash.hexdigest()
            flags = 0
            if attr['is_pkg']:
                flags |= FLAG_PKG
            if attr['is_binary']:
                flags |= FLAG_BIN

            mod_data = b''
            mod_data += struct.pack('<32s', name_hash.digest())
            mod_data += struct.pack('<B', flags)
            mod_data += struct.pack('<32s', attr['key'])
            mod_data += struct.pack('<32s', attr['hash'])
            body += mod_data

        # Sign manifest
        key = RSA.importKey(open(self.config.MANIFEST_PRIVKEY).read())
        h = SHA512.new()
        # Sign header and body
        h.update(header)
        h.update(body)
        signer = PKCS1_PSS.new(key)
        signature = signer.sign(h)

        with bin_path.open('wb') as ofile:
            ofile.write(header)
            ofile.write(signature)
            ofile.write(body)
        return infos

    def verify_signature(self):
        """Check the manifest signature"""
        self.get_data()
        signature = self.__data[:512]
        data = self.__data[512:]
        key = RSA.importKey(open(self.config.MANIFEST_PUBKEY).read())
        hashalgo = SHA512.new()
        hashalgo.update(data)
        verifier = PKCS1_PSS.new(key)
        return verifier.verify(hashalgo, signature)

    def get_timestamp(self):
        """Get the manifest timestamp"""
        if self.__timestamp == 0:
            self.get_data()
        return self.__timestamp

    def get_data(self):
        """Returns the manifest"""
        if self.__data:
            return self.__data
        bin_path = Path(self.config.BIN_PATH, 'manifest.bin')
        self.__data = bin_path.read_bytes()
        data = BytesIO(self.__data[512:])
        self.__timestamp = unpack(data, '<Q')[0]
        return self.__data

    def get_manifest(self):
        """Parse the current manifest"""
        infos = {}
        data = BytesIO(self.get_data()[512:])
        infos['timestamp'] = unpack(data, '<Q')[0]
        infos['signature'] = self.verify_signature()
        infos['modules'] = {}
        while True:
            mod = Module.from_data(data)
            if not mod:
                break
            infos['modules'][binascii.hexlify(mod.mod_hash)] = mod.to_dict()
        return infos

    def __crypt_code(self, key, data):
        aes_iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, aes_iv)
        msg = aes_iv + cipher.encrypt(data)
        return msg

    def build_manifest(self):
        """Actually build the manifest"""
        self.__get_extra_paths()
        for code_path in self.__code_path:
            for item in code_path.glob('**/*'):
                if item.is_dir():
                    continue

                ext = item.suffix
                relitem = self.__get_best_relative(item)

                skip = False
                for excl in EXCLUDE_FROM_LIBRARY:
                    if re.match(excl, str(relitem)):
                        skip = True
                        break
                if skip:
                    continue

                module = '{}'.format(
                    str(relitem.as_posix()).replace(ext, '').replace('/', '.'))

                is_pkg = False
                if item.stem == '__init__':
                    module = module.replace('.__init__', '')
                    is_pkg = True

                if ext == '.py':
                    codename = '<epcode/{}>'.format(relitem)  # TODO: remove {} in prod
                    data = compile(
                        item.read_bytes(),
                        codename,
                        'exec',
                        dont_inherit=False,
                        optimize=2)
                    bincode = marshal.dumps(data)

                    key = Random.new().read(32)
                    bincode = self.__crypt_code(key, bincode)

                    hashcode = sha256(bincode)
                    filename = sha256(module.encode('ascii')).hexdigest()
                    self.__write_output(bincode, filename)

                    self.manifest[module] = {
                        'is_pkg': is_pkg,
                        'hash': hashcode.digest(),
                        'key': key,
                        'is_binary': False
                    }
                elif ext in ['.pyd', '.so']:
                    module = str(Path(module).stem)
                    data = item.read_bytes()

                    key = Random.new().read(32)
                    data = self.__crypt_code(key, data)

                    hashcode = sha256(data)
                    # Remove platform tags
                    filename = sha256(module.encode('ascii')).hexdigest()
                    self.__write_output(data, filename)
                    self.manifest[module] = {
                        'is_pkg': True,
                        'hash': hashcode.digest(),
                        'key': key,
                        'is_binary': True
                    }
        return self.manifest
