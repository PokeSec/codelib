"""
http_blob.py : Http blob channel

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
from epc.common.cache import Cache
from epc.common.comm import req_sess, CommException
from epc.common.data.channel import DataChannel
from epc.common.exceptions import DataError


class HttpBlobDataChannel(DataChannel):
    """Get / store blobs from http"""

    def get(self, key: str, use_cache=True):
        """Get some data"""
        cache_key = "HttpBlob/{}".format(key)
        if use_cache:
            data = Cache().get(cache_key)
            if data:
                return data
        try:
            req = req_sess.get('data_blob/{}'.format(key))
            if req.status_code != 200:
                raise DataError("Got response status code", req.status_code)
            data = req.content
            Cache().set(cache_key, data, tag='blob')
            return data
        except CommException as e:
            raise DataError from e

    def send(self, key: str, data):
        """Send some data"""
        try:
            req = req_sess.post(
                'data/{}'.format(key),
                data=data)
            if req.status_code != 200:
                raise DataError("Got response status code", req.status_code)
            else:
                return True
        except CommException as e:
            raise DataError from e

    def flush(self):
        """Flush the data (does nothing here)"""
        pass
