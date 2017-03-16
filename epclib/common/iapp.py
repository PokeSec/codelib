"""
iapp.py : Interface for apps

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
from typing import Optional

from epc.common.settings import Config
from epclib.common.utils import ThreadWithReturnValue


class App(object):
    """Base class for apps"""
    _runmode = 'thread' if Config().PLATFORM == 'android' else 'standalone'

    def __init__(self):
        self._thread = None
        self.__is_running = False
        self.logger = None

    @property
    def is_running(self):
        if self._runmode == "thread":
            return self._thread.isAlive()
        else:
            return self.__is_running

    def __run_t(self, *args, **kwargs) -> Optional[ThreadWithReturnValue]:
        if not kwargs:
            kwargs = {}

        target = getattr(self, '_run', None)
        if target and callable(target):
            self._thread = ThreadWithReturnValue(target=target, args=args, kwargs=kwargs)
            self._thread.start()
            return self._thread
        return None

    def run(self, args=(), kwargs=None):
        """Run the app"""
        if not kwargs:
            kwargs = {}
        if self._runmode == 'standalone':
            target = getattr(self, '_run', None)
            if target and callable(target):
                self.__is_running = True
                ret_code = target(*args, **kwargs)
                args[0].value = ret_code
                return ret_code
        elif self._runmode == 'thread':
            return self.__run_t(*args, **kwargs)
        return None

    def stop(self):
        """Stop the app"""
        stopfunc = getattr(self, '_stop', None)
        if stopfunc and callable(stopfunc):
            stopfunc()
            self.__is_running = False
