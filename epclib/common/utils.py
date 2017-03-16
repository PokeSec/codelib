"""
utils.py : Common utilities for agentlib

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
import logging
from threading import Thread


class ThreadWithReturnValue(Thread):
    """Thread class used to make join() return the value returned from thread execution"""

    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)
        self._return = None

    def run(self):
        if self._target is not None:
            try:
                self._return = self._target(*self._args, **self._kwargs)
            except:
                logging.exception("Uncaught exception in thread")
                self._return = -1
            finally:
                # Detach Jnius on Android
                try:
                    import jnius
                    jnius.detach()
                except:
                    pass

    def join(self, timeout=None):
        Thread.join(self, timeout)
        return self._return
