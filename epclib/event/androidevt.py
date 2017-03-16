"""
androidevt.py : Android event monitor

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
import threading

from epc.android.scheduler import AndroidScheduler
from epc.android.service import service
from epclib.event.event import Monitor, Event


class AndroidEventMonitor(Monitor):
    """Register callbacks for Android events"""

    ACTIONS = {
        Event.software_installed: 'android.intent.action.PACKAGE_ADDED',
        Event.software_removed: 'android.intent.action.PACKAGE_REMOVED'
    }

    def __init__(self):
        self.__stop_event = threading.Event()
        self.scheduler = service.scheduler  # type: AndroidScheduler
        self.registered = []

    def run(self) -> bool:
        self.__stop_event.wait()
        return True

    def add_callback(self, event: Event, callback: callable) -> bool:
        """Add a callback"""
        try:
            action = AndroidEventMonitor.ACTIONS[event]
            self.scheduler.register_action(action, callback)
            self.registered.append((action, callback))
            logging.debug("AndroidEventMonitor, Registered callback for %s, %s => %s", event, action, callback)
            return True
        except KeyError:
            return False

    def stop(self) -> bool:
        for event, callback in self.registered:
            self.scheduler.unregister_action(event, callback)
            logging.debug("AndroidEventMonitor, unregistered callbacks %s => %s", event, callback)
        self.__stop_event.set()
        return True
