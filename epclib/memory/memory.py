"""
memory.py : RAM dump

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
import tempfile
from subprocess import Popen, PIPE

from epc.common.data import DataClient
from epc.common.settings import Config


class RamDumper(object):
    def __init__(self, compression='snappy'):
        if Config().PLATFORM == 'win':
            self.__binary = 'winpmem-2.1.post4.exe'
            self.__dumpfunc = self.__dump_win
        elif Config().PLATFORM == 'linux':
            self.__binary = 'linpmem-2.1.post4'
            self.__dumpfunc = self.__dump_linux
        elif Config().PLATFORM == 'osx':
            self.__binary = 'osxpmem-2.1.post4.zip'
            self.__dumpfunc = self.__dump_osx
        else:
            raise NotImplementedError()

        self.compression = compression

    def __dump_win(self, data):
        with tempfile.NamedTemporaryFile(
                dir=Config().BINCACHE_DIR,
                suffix='.exe') as tmp:
            tmp.write(data)
            tmp.flush()
            with Popen([
                tmp.name,
                '--acquire-memory',
                '--compression', self.compression,
                '--output', '-'
            ], stdout=PIPE, stderr=PIPE) as proc:
                # TODO: store/send the data
                pass

    def __dump_linux(self, data):
        pass

    def __dump_osx(self, data):
        pass

    def dump(self):
        if callable(self.__dumpfunc):
            # Ensure the BINCACHE_DIR exists
            os.makedirs(Config().BINCACHE_DIR, exist_ok=True)
            return self.__dumpfunc(DataClient().get('http_blob', self.__binary))
        raise NotImplementedError()
