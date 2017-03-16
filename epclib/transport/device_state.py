"""
device_state.py : Reporting Channel

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
import json
from json import JSONEncoder

import arrow
from epc.common.cache import Cache
from epc.common.comm import req_sess, CommException
from epc.common.data.channel import DataChannel
from epc.common.exceptions import DataError


class CustomJSONEncoder(JSONEncoder):
    def default(self, o):
        return None


class DeviceStateChannel(DataChannel):
    """Get / store blobs from http"""

    def __init__(self):
        self.__data = Cache().get('device_state')
        if self.__data:
            Cache().delete('device_state')
        else:
            self.__data = dict()

    def __send_data(self, force=False):
        if len(self.__data) == 0:
            return True

        try:
            req = req_sess.post(
                'data_state',
                headers={'Content-Type': 'application/json'},
                data=json.dumps(self.__data, cls=CustomJSONEncoder))
            if req.status_code not in [200, 201]:
                raise DataError("Got response status code", req.status_code)
            else:
                self.__data.clear()
                return True
        except CommException as e:
            raise DataError from e

    def get(self, key, use_cache=True):
        """Get is not implemented for this channel"""
        raise NotImplementedError("Get is not implemented for this channel")

    def send(self, key: str, data):
        """
        Send a report

        data must be a dict and be JSON serializable
            The data may have a _timestamp attribute, otherwise the method will set it to the current timestamp
        """
        now = arrow.utcnow().isoformat()
        if 'timestamp' not in data:
            data['timestamp'] = now
            self.__data[key] = data
        return True

    def flush(self):
        """Flush the data"""
        try:
            self.__send_data(force=True)
        except CommException:
            Cache().set('device_state', self.__data, tag='data')

    def notify(self):
        print("NOTIFIED!")
