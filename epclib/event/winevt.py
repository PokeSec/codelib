"""
winevt.py : Watch events from sysmon logs

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
import threading
import win32evtlog
from xml.etree.ElementTree import Element

import psutil
from defusedxml import ElementTree

from epclib.event.event import Monitor, Event


class Process(psutil.Process):
    pass


SYSMON_EVENTID_MAP = {
    1: Event.process_created,
    2: None,  # Change file creation time
    3: None,  # Network conn
    4: None,  # Sysmon state changed
    5: Event.process_stopped,
    6: Event.driver_loaded,
    7: None,  # Dll loaded
    8: Event.process_debugged,  # Create remote thread
    9: None,  # Raw access to disk
    10: Event.process_debugged,  # Process open
}


class WinEventMonitor(Monitor):
    def __init__(self):
        self.__stop_event = threading.Event()
        self.__callbacks = dict()
        for event in list(Event):
            self.__callbacks[event] = []
        self.__subscriptions = dict()

        self.__event_sources = {
            Event.process_created: [
                'Microsoft-Windows-Sysmon/Operational',
                'Security'
            ],
            Event.process_stopped: [
                'Microsoft-Windows-Sysmon/Operational',
            ],
            Event.process_debugged: [
                'Microsoft-Windows-Sysmon/Operational',
            ],
            Event.driver_loaded: [
                'Microsoft-Windows-Sysmon/Operational',
            ],
        }

        self.__event_parsers = {
            'Microsoft-Windows-Sysmon/Operational': self.__parse_sysmon_event,
            'Security': None
        }

        self.processes = {p.pid: Process(p.pid) for p in psutil.process_iter()}

        def _get_process(self, pid):
            try:
                return self.processes.setdefault(pid, Process(pid))
            except Exception as e:
                return None

    def subscribe(self, log_name, query='*'):
        if log_name in self.__subscriptions:
            return True
        try:
            subscription = win32evtlog.EvtSubscribe(
                log_name,
                win32evtlog.EvtSubscribeToFutureEvents,
                Query=query,
                Callback=self.__log_callback,
                Context=log_name)
            self.__subscriptions[log_name] = subscription
        except win32evtlog.error:
            return False
        return True

    def _get_process(self, pid):
        try:
            return self.processes.setdefault(pid, Process(pid))
        except Exception as e:
            return None

    def run(self):
        self.__stop_event.wait()

    def stop(self):
        self.__stop_event.set()

    def __log_callback(self, reason, context, evt):
        if reason == win32evtlog.EvtSubscribeActionDeliver:
            parser = self.__event_parsers.get(context)
            if parser:
                event, data = parser(win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml))
                if event:
                    for callback in self.__callbacks[event]:
                        callback(**data)
        return 0

    def add_callback(self, event: Event, callback: callable) -> bool:
        """
        EM.add_callback(callback) -> bool -- add an event callback
        """
        # Ensure the subscription for the required event
        for event_source in self.__event_sources.get(event, []):
            if self.subscribe(event_source):
                if callback not in self.__callbacks:
                    self.__callbacks[event].append(callback)
                return True
        return False

    def __parse_sysmon_event(self, evt):
        ns = {
            'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'
        }

        root = ElementTree.fromstring(evt)  # type: Element
        event_id = int(root.find('evt:System/evt:EventID', ns).text)
        event = SYSMON_EVENTID_MAP.get(event_id)
        if not event:
            return None, None
        data = dict()
        for item in root.findall('evt:EventData/evt:Data', ns):
            name = item.get('Name', None)
            if name:
                data[name] = item.text
        try:
            pid = int(data.get('ProcessId'))
            data['process'] = self._get_process(pid)
        except (KeyError, TypeError):
            pass
        try:
            pid = int(data.get('SourceProcessId'))
            data['source_process'] = self._get_process(pid)
            pid = int(data.get('TargetProcessId'))
            data['target_process'] = self._get_process(pid)
        except (KeyError, TypeError):
            pass
        return event, data
