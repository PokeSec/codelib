"""
event.py : Common items for monitoring

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
from abc import ABCMeta, abstractmethod
from enum import Enum


class Event(Enum):
    software_installed = 1
    software_removed = 2
    network_changed = 3

    # PC only
    process_created = 101
    process_stopped = 102
    process_core_dumped = 103
    process_owner_changed = 104
    process_debugged = 105
    driver_loaded = 106
    driver_unloaded = 107
    remote_thread_created = 108


class Monitor(metaclass=ABCMeta):
    @abstractmethod
    def run(self) -> bool:
        ...

    @abstractmethod
    def stop(self) -> bool:
        ...

    @abstractmethod
    def add_callback(self, event: Event, callback: callable) -> bool:
        ...
