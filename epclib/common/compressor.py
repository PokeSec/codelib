"""
compressor.py : Compression / Decompression helpers

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
import zlib

support = dict(
    lzma=False,
    bz2=False,
)
try:
    import lzma

    support['lzma'] = True
except ImportError:
    pass
try:
    import bz2

    support['bz2'] = True
except ImportError:
    pass


class Compressor(object):
    @classmethod
    def get(cls):
        if support['lzma']:
            return b'LZ00', lzma.LZMACompressor()
        elif support['bz2']:
            return b'BZ00', bz2.BZ2Compressor()
        else:
            return b'ZL00', zlib.compressobj()


class Decompressor(object):
    @classmethod
    def get(cls, algo: str):
        if algo == 'lzma' and support['lzma']:
            return lzma.LZMADecompressor()
        elif algo == 'bz2' and support['bz2']:
            return bz2.BZ2Decompressor()
        else:
            return zlib.decompressobj()

    @classmethod
    def from_header(cls, header: bytes):
        if header == b'LZ00' and support['lzma']:
            return lzma.LZMADecompressor()
        elif header == b'BZ00' and support['bz2']:
            return bz2.BZ2Decompressor()
        else:
            return zlib.decompressobj()
