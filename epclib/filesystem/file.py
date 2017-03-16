"""
file.py : File Objects

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
import array
import hashlib
import io
import logging
import math
import numbers
import os
import yara
from functools import partial
from pathlib import Path

try:
    import pytsk3

    TSK_SUPPORT = True
except ImportError:
    TSK_SUPPORT = False
    pass
try:
    from pefile import PE, PEFormatError

    PEFILE_SUPPORT = True
except ImportError:
    PEFILE_SUPPORT = False
    pass


def old_div(a, b):
    """
    Equivalent to ``a / b`` on Python 2 without ``from __future__ import
    division``.

    TODO: generalize this to other objects (like arrays etc.)
    """
    if isinstance(a, numbers.Integral) and isinstance(b, numbers.Integral):
        return a // b
    else:
        return a / b


class EntropyCompute(object):
    """Get the entropy of some data"""

    def __init__(self):
        self.__occurences = array.array('L', [0] * 256)
        self.__data_count = 0

    def update(self, data):
        self.__data_count += len(data)
        for item in data:
            self.__occurences[item if isinstance(item, int) else ord(item)] += 1

    def get_entropy(self):
        entropy = 0
        for occ in self.__occurences:
            if occ:
                p_x = old_div(float(occ), self.__data_count)
                entropy -= p_x * math.log(p_x, 2)
        return entropy


class _File(object):
    """
    Generic file object
    Must be specialized
    """
    HASH_TYPES = dict(
        md5=hashlib.md5,
        sha1=hashlib.sha1,
        sha256=hashlib.sha256,
        sha512=hashlib.sha512,
    )
    BUF_SIZE = 1024 * 1024

    def __init__(self):
        self._hashes = dict()
        self.read_mode = 'raw'

    def get_data(self, name=None, mode=None):
        """
        Return some data from the file

        Args:
            name: None or the name of the data stream
            mode: The way to read files

        Returns:
            byte object
            None
        """
        return None

    def is_deleted(self):
        """Return if a file is deleted"""
        return False

    def get_hashes(self, name):
        if name in self._hashes:
            return self._hashes[name]

        data_file = self.get_data(name, self.read_mode)
        if not data_file:
            return None

        try:
            self._hashes[name] = dict()
            for hash_type, hash_class in self.HASH_TYPES.items():
                self._hashes[name][hash_type] = hash_class()

            for buf in iter(partial(data_file.read, self.BUF_SIZE), b''):
                for hash_type in self.HASH_TYPES.keys():
                    self._hashes[name][hash_type].update(buf)
            return self._hashes[name]
        finally:
            data_file.close()

    def get_hash_md5(self, name=None):
        """Get the MD5 hex-digest of the file."""
        hashes = self.get_hashes(name)
        if hashes and hashes.get('md5'):
            return hashes.get('md5').hexdigest()
        return None

    def get_hash_sha1(self, name=None):
        """Get the SHA-1 hex-digest of the file."""
        hashes = self.get_hashes(name)
        if hashes and hashes.get('sha1'):
            return hashes.get('sha1').hexdigest()
        return None

    def get_hash_sha256(self, name=None):
        """Get the SHA-256 hex-digest of the file."""
        hashes = self.get_hashes(name)
        if hashes and hashes.get('sha256'):
            return hashes.get('sha256').hexdigest()
        return None

    def get_hash_sha512(self, name=None):
        """Get the SHA-512 hex-digest of the file."""
        hashes = self.get_hashes(name)
        if hashes and hashes.get('sha512'):
            return hashes.get('sha512').hexdigest()
        return None

    def get_entropy(self, name=None):
        """Calculate and return the entropy for the file."""
        hashes = self.get_hashes(name)
        if hashes and hashes.get('entropy'):
            return hashes.get('entropy').get_entropy()
        return None

    def scan_yara(self, rules, ads=None, fast=False):
        """Scan the file using yara rules"""
        raise NotImplementedError()


class TSKData(io.BufferedIOBase):
    BUF_SIZE = 1024 * 1024

    def __init__(self, directory_entry, stream):
        super(TSKData, self).__init__()
        self.__offset = 0
        self.__directory_entry = directory_entry
        self.__stream = stream

    def readable(self):
        return True

    def read(self, n=-1):
        """
        Read and return up to n bytes.
        If the argument is omitted, None, or negative, data is read and returned until EOF is reached..
        """
        available_to_read = min(n, self.__stream['size'] - self.__offset)
        if available_to_read <= 0:
            return b''

        data = self.__directory_entry.read_random(
            offset=self.__offset,
            len=available_to_read,
            type=self.__stream['type'],
            id=self.__stream['id']
        )
        self.__offset += len(data)
        return data

    def read1(self, n):
        """Read up to n bytes with at most one read() system call."""
        to_read = min(self.BUF_SIZE, n)
        available_to_read = min(to_read, self.__stream['size'] - self.__offset)
        if available_to_read <= 0:
            return b''

        data = self.__directory_entry.read_random(
            offset=self.__offset,
            len=available_to_read,
            type=self.__stream['type'],
            id=self.__stream['id']
        )
        self.__offset += len(data)
        return data

    def seekable(self):
        return True

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self.__offset = offset
        elif whence == io.SEEK_CUR:
            self.__offset += offset
        elif whence == io.SEEK_END:
            self.__offset = self.__stream['size'] + offset
        return self.__offset

    def tell(self):
        return self.__offset

    def close(self):
        """Close the file"""
        pass

    def detach(self):
        raise io.UnsupportedOperation


class TSKFile(_File):
    """
    Concrete implementation of file for TSK volumes
    """

    def __init__(self, drive, directory_entry, parent_path):
        if not TSK_SUPPORT:
            raise NotImplementedError()
        super(TSKFile, self).__init__()
        self.__drive = drive
        self.__directory_entry = directory_entry
        self.__parent_path = parent_path
        self.__meta = self.__directory_entry.info.meta
        self.__name = self.__directory_entry.info.name
        self.__attrs = dict(
            filename=self.__name.name,
            streams={},
            path=self.__parent_path / self.__name.name.decode('utf-8', errors='replace'),
        )
        self.__parse()
        self.pe_data = None

    def __parse(self):
        for attribute in self.__directory_entry:
            inode_type = int(attribute.info.type)
            if inode_type in [
                pytsk3.TSK_FS_ATTR_TYPE_NTFS_IDXROOT,
                pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA,
                pytsk3.TSK_FS_ATTR_TYPE_DEFAULT]:
                attribute_name = attribute.info.name

                attrs = dict(
                    inode="{0:d}-{1:d}-{2:d}".format(self.__meta.addr, int(attribute.info.type), attribute.info.id),
                    size=attribute.info.size,
                    type=int(attribute.info.type),
                    id=attribute.info.id,
                    mode=int(self.__meta.mode),
                    uid=self.__meta.uid,
                    gid=self.__meta.gid,
                    ctime=self.__meta.ctime,
                    mtime=self.__meta.mtime,
                    atime=self.__meta.atime,
                )

                self.__attrs['streams'][
                    attribute_name.decode('utf-8', errors='replace') if attribute_name else '$Data'] = attrs

    def __getattr__(self, item):
        return self.__attrs.get(item)

    def is_directory(self):
        """Returns if a file is a directory"""
        if self.__name:
            return self.__name.type == pytsk3.TSK_FS_NAME_TYPE_DIR
        elif self.__meta:
            return self.__meta.type == pytsk3.TSK_FS_META_TYPE_DIR

    def is_deleted(self):
        """Returns if a file is deleted"""
        if self.__name:
            return int(self.__name.flags) & pytsk3.TSK_FS_NAME_FLAG_UNALLOC != 0

    def get_data(self, name=None, mode='raw'):
        """
        Return some data from the file

        Args:
            name: None or the name of the data stream3
            mode: The way to read files:
              - 'raw' reads the data from the disk (slow, but bypass security and locks)
              - 'standard' uses the standard API to read files (fast, can fail because of security descriptors or locks)

        Returns:
            File-like object
            None
        """
        if not name:
            name = '$Data'
        stream = self.__attrs['streams'].get(name)
        if not stream:
            return None

        if mode == 'standard':
            if name == '$Data':
                path = self.__attrs['path']
            else:
                path = self.__parent_path / '{}:{}'.format(self.__name.name.decode('utf-8', errors='replace'), name)
            return path.open('rb')
        elif mode == 'raw':
            return TSKData(self.__directory_entry, stream)
        return None

    def scan_yara(self, rules, ads=None, fast=False):
        """Scan the file using yara rules"""
        matches = []
        for rule in rules:
            try:
                matches += rule.match(
                    data=self.get_data(ads).read(),
                    fast=fast,
                    externals={
                        'filename': self.path.name,
                        'filepath': str(self.path),
                        'extension': self.path.suffix,
                        'filetype': '-',
                        'md5': self.get_hash_md5(ads)
                    })
            except yara.Error:
                logging.exception("Yara error")
        return matches

    def get_pe(self, force=False):
        """
        Returns the pefile.PE object if the file is actually a PE

        Args:
            force: Disable extension detection for PE files (default False)

        Returns:
            pefile.PE
            None
        """
        if not PEFILE_SUPPORT:
            return None
        if force or self.__attrs['path'].suffix in ['.dll', '.exe', '.sys']:
            try:
                data = self.get_data()
                self.pe_data = PE(name=str(self.__attrs['path']), data=data, fast_load=True)
                return self.pe_data
            except PEFormatError:
                return None
            except Exception:
                return None
        return None

    def __repr__(self):
        return "{} {}".format(self.__attrs['path'], self.__attrs['path'].suffixes)


class AndroidFile(_File):
    def __init__(self, entry):
        super(AndroidFile, self).__init__()
        self.read_mode = 'standard'
        self.__entry = entry
        self._follow_symlinks = False
        stat = entry.stat(follow_symlinks=self._follow_symlinks)  # type: os.stat_result
        self.streams = {
            None: dict(
                size=stat.st_size,
                mode=stat.st_mode,
                inode=stat.st_ino,
                uid=stat.st_uid,
                gid=stat.st_gid,
                ctime=stat.st_ctime,
                mtime=stat.st_mtime,
                atime=stat.st_atime,
            )
        }

    def is_directory(self):
        return self.__entry.is_dir(follow_symlinks=self._follow_symlinks)

    def get_data(self, name=None, mode='standard'):
        if mode != 'standard' or name:
            raise NotImplementedError()
        return self.path.open('rb')

    @property
    def path(self):
        return Path(self.__entry.path)

    def scan_yara(self, rules, _=None, fast=False):
        """Scan the file using yara rules"""
        matches = []
        for rule in rules:
            try:
                matches += rule.match(
                    filepath=str(self.path),
                    fast=fast,
                    externals={
                        'filename': self.path.name,
                        'filepath': str(self.path),
                        'extension': self.path.suffix,
                        'filetype': '-',
                        'md5': self.get_hash_md5()
                    })
            except yara.Error:
                logging.exception("Yara error")
        return matches
