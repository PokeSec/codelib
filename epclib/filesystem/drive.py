"""
drive.py : Computer drive management functions

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
import os
from pathlib import Path
from typing import Iterator

from epc.common.platform import PlatformData
from epc.common.settings import Config
from .file import TSKFile, AndroidFile


class DriveManager(object):
    def __init__(self):
        if Config().PLATFORM == 'android':
            self.__class = self.AndroidDrive
        else:
            self.__class = self.TSKDrive

    def open(self, drive_name, basepath=None):
        return self.__class(drive_name, basepath)

    @staticmethod
    def list_available(filesystems=None):
        """
        Get the available drives

        Returns a tupple: (disk, mountpoint)
        """
        drives = []
        if Config().PLATFORM == 'win32':
            try:
                # Windows method
                import string
                import win32api
                import win32file
                bitmask = win32api.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drive_type = win32file.GetDriveType('{}:\\'.format(letter))
                        if drive_type in [win32file.DRIVE_FIXED]:
                            if filesystems:
                                if win32api.GetVolumeInformation('{}:\\'.format(letter))[4] in filesystems:
                                    drives.append((r'\\.\{}:'.format(letter), '{}:\\'.format(letter)))
                            else:
                                drives.append((r'\\.\{}:'.format(letter), '{}:\\'.format(letter)))
                    bitmask >>= 1
                return drives
            except ImportError:
                pass
        elif Config().PLATFORM == 'unix':
            if PlatformData('unix').get_data().get('osversion') == 'osx':
                try:
                    # OSX method
                    import plistlib
                    from sh import diskutil
                    data = plistlib.loads(diskutil('list', '-plist').stdout)
                    for item in data.get('AllDisksAndPartitions', []):
                        mountpoint = item.get('MountPoint')
                        if not mountpoint:
                            continue  # Ignore not mounted file systems
                        if filesystems and not item.get('Content').split('_')[-1] in filesystems:
                            continue
                        drives.append(('/dev/r{}'.format(item['DeviceIdentifier']), mountpoint))
                    return drives
                except (ImportError, ValueError):
                    pass
        try:
            # Linux and Android method
            with open('/proc/mounts') as ifile:
                for lines in ifile.readlines():
                    infos = lines.split(' ')
                    if not infos[0].startswith('/'):
                        continue  # Don't scan virtual file systems
                    if filesystems and not infos[2] in filesystems:
                        continue
                    drives.append((infos[0], infos[1]))
        except FileNotFoundError:
            pass

        if Config().PLATFORM == 'android':
            drives.append(('/sdcard', '/sdcard'))

        return drives

    class Drive(object):
        """
        Generic Drive object
        Must be specialized
        """

        def __init__(self, drive_name, basepath=None):
            self._drive_name = drive_name
            self._basepath = basepath if basepath else self._drive_name
            self.drive_fd = 0

            self._recursive = True

        def enumerate_files(self, directory=None, recurse_callback=None):
            """
            Enumerates the files from the drive

            Args:
                directory: base directory (default Root of drive)
                recurse_callback: callback used for recursion control (default None)

            :rtype: Iterator[_File]
            """
            if not directory:
                directory = [self._basepath]
            elif not isinstance(directory, list):
                directory = [directory]

            for d in directory:  # type: str
                try:
                    # Remove the drive letter for windows if the relative path has no drive letter
                    cleanbase = self._basepath[2:] if self._basepath[1] == ':' and d[1] != ':' else self._basepath
                    basepath = Path('/') / Path(d + os.path.sep).relative_to(cleanbase)
                except ValueError:
                    # relative_to raises a ValueError is the paths are not relatives
                    continue
                odir = self._open_directory(basepath.as_posix())
                for item in self._list_directory(
                        odir,
                        stack=[],
                        parent_path=basepath,
                        recurse_callback=recurse_callback):
                    yield item

        def _open_directory(self, inode_or_path):
            raise NotImplementedError()

        def _list_directory(self, directory, stack=None, parent_path=Path('/'), recurse_callback=None):
            raise NotImplementedError()

        def read_disk(self, size, pos=None, pos_mode=os.SEEK_SET):
            raise NotImplementedError()

    class AndroidDrive(Drive):
        """
        AndroidDrive object
        """

        def __init__(self, drive_name, basepath=None):
            super(DriveManager.AndroidDrive, self).__init__(drive_name, basepath)

        def read_disk(self, size, pos=None, pos_mode=os.SEEK_SET):
            raise NotImplementedError()

        def _open_directory(self, inode_or_path):
            return str(Path(inode_or_path).relative_to('/'))

        def _list_directory(self, directory, stack=None, parent_path=Path('/'), recurse_callback=None):
            for entry in os.scandir(os.path.join(self._basepath, directory)):
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if self._recursive:
                            if recurse_callback:
                                try:
                                    if not recurse_callback(Path(entry.path)):
                                        continue
                                except:
                                    continue
                        yield from self._list_directory(entry.path, stack, parent_path / entry.path, recurse_callback)
                    else:
                        yield AndroidFile(entry)
                except OSError:
                    continue

    class TSKDrive(Drive):
        """
        TSK Drive object, used for non-mobile endpoints
        """

        def __init__(self, drive_name, basepath=None):
            super(DriveManager.TSKDrive, self).__init__(drive_name, basepath)
            import pytsk3
            self.__img_info = pytsk3.Img_Info(self._drive_name)
            self._fs_info = pytsk3.FS_Info(self.__img_info)

        def _open_directory(self, inode_or_path):
            """Open a directory"""
            inode = None
            path = None

            if isinstance(inode_or_path, int):
                inode = inode_or_path
            elif inode_or_path is None:
                path = "/"
            elif Config().PLATFORM == 'win32' and not inode_or_path[3:]:
                path = "/"
            else:
                path = inode_or_path

            # Note that we cannot pass inode=None to fs_info.opendir().
            if inode:
                directory = self._fs_info.open_dir(inode=inode)
            else:
                directory = self._fs_info.open_dir(path=path)

            return directory

        def _list_directory(self, directory, stack=None, parent_path=Path('/'), recurse_callback=None):
            """
            List a previously opened folder

            Returns:
                Yields File
            """
            stack.append(directory.info.fs_file.meta.addr)

            for directory_entry in directory:
                # Skip ".", ".." or directory entries without a name.
                if (not hasattr(directory_entry, "info") or
                        not hasattr(directory_entry.info, "name") or
                        not hasattr(directory_entry.info.name, "name") or
                            directory_entry.info.name.name in [".", "..", b".", b".."]):
                    continue

                myfile = TSKFile(self, directory_entry, parent_path)
                yield myfile

                if self._recursive:
                    if recurse_callback:
                        try:
                            if not recurse_callback(myfile.path):
                                continue
                        except:
                            continue
                    try:
                        sub_directory = directory_entry.as_directory()
                        inode = directory_entry.info.meta.addr

                        # This ensures that we don't recurse into a directory
                        # above the current level and thus avoid circular loops.
                        if inode not in stack:
                            for item in self._list_directory(
                                    sub_directory,
                                    stack=stack,
                                    parent_path=myfile.path,
                                    recurse_callback=recurse_callback):
                                yield item

                    except IOError:
                        pass

            stack.pop(-1)

        def read_disk(self, size, pos=None, pos_mode=os.SEEK_SET):
            """
            Read some data from the disk

            Args:
                size: number of bytes to read
                pos: offset from the start
                pos_mode: lseek-like pos_mose (SEEK_SET, SEEK_CUR, ...)

            Returns:
                a bytes object
            """
            if pos is not None:
                os.lseek(self.drive_fd, pos, pos_mode)
            data = os.read(self.drive_fd, size)
            return data
