"""
cm_proc.py : Monitor Linux process events

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
import hashlib
import logging
import os
import socket
import struct
import threading
from enum import Enum
from functools import partial

import psutil

from epclib.event.event import Monitor, Event

CN_IDX_PROC = 1
CN_VAL_PROC = 1

NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLMSG_OVERRUN = 4

PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2


class Process(psutil.Process):
    """Wrapper around psutil.Process allowing the user to get access to a cached dict data in case of Process death"""
    HASH_TYPES = ['md5', 'sha1', 'sha256']
    BUF_SIZE = 1024 * 1024

    def __init__(self, pid=None):
        try:
            super(Process, self).__init__(pid)
            self.__dict = super(Process, self).as_dict()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            self.__dict = dict(
                pid=exc.pid,
                name=exc.name,
                error=exc
            )
        self._hashes = dict()

    def as_dict(self, attrs=None, ad_value=None):
        return self.__dict

    def get_hashes(self):
        if not self._hashes:
            try:
                with open(self.__dict['exe'], 'rb') as ifile:
                    for hash_type in self.HASH_TYPES:
                        self._hashes[hash_type] = hashlib.new(hash_type)

                    for buf in iter(partial(ifile.read, self.BUF_SIZE), b''):
                        for hash_type in self.HASH_TYPES:
                            self._hashes[hash_type].update(buf)
            except (OSError, KeyError):
                pass
        return self._hashes


class LinuxEventMonitor(Monitor):
    """Event monitor using Netlink sockets and kernel CN_PROC messages"""

    class ProcEvent(Enum):
        NONE = 0
        FORK = 1
        EXEC = 2
        UID = 4
        GID = 0x40
        SID = 0x80
        PTRACE = 0x100
        COMM = 0x200
        CORE_DUMP = 0x40000000
        EXIT = 0x80000000

    EVENTS_MAP = {
        Event.process_created: (ProcEvent.FORK,),
        Event.process_stopped: (ProcEvent.EXIT,),
        Event.process_debugged: (ProcEvent.PTRACE,),
        Event.process_core_dumped: (ProcEvent.CORE_DUMP,),
        Event.process_owner_changed: (ProcEvent.UID, ProcEvent.GID)
    }

    def __init__(self):
        self.thread = None
        self.processes = {p.pid: Process(p.pid) for p in psutil.process_iter()}
        self.callbacks = {event: [] for event in LinuxEventMonitor.ProcEvent}

        # Create Netlink socket
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, getattr(socket, "NETLINK_CONNECTOR", 11))
        self.sock.bind((os.getpid(), CN_IDX_PROC))

        # Send PROC_CN_MCAST_LISTEN
        data = struct.pack("=IHHII IIIIHH I",
                           16 + 20 + 4, NLMSG_DONE, 0, 0, os.getpid(),
                           CN_IDX_PROC, CN_VAL_PROC, 0, 0, 4, 0,
                           PROC_CN_MCAST_LISTEN)
        if self.sock.send(data) != len(data):
            raise RuntimeError("Failed to send PROC_CN_MCAST_LISTEN")

    def _get_process(self, pid):
        try:
            return self.processes.setdefault(pid, Process(pid))
        except Exception as e:
            return None

    def run(self):
        """Main loop, call self.stop() to end the loop"""
        while True:
            try:
                data, (nlpid, nlgrps) = self.sock.recvfrom(1024)
            except OSError:
                logging.info("Socket closed, exiting LinuxEventMonitor loop")
                break

            # Netlink message header (struct nlmsghdr)
            msg_len, msg_type, msg_flags, msg_seq, msg_pid \
                = struct.unpack("=IHHII", data[:16])
            data = data[16:]

            if msg_type == NLMSG_NOOP:
                continue
            if msg_type in (NLMSG_ERROR, NLMSG_OVERRUN):
                break

            # Connector message header (struct cn_msg)
            cn_idx, cn_val, cn_seq, cn_ack, cn_len, cn_flags = struct.unpack("=IIIIHH", data[:20])
            data = data[20:]

            # Process event message (struct proc_event)
            what, cpu, timestamp = struct.unpack("=LLQ", data[:16])
            data = data[16:]

            # FIXME: Factorize this ugliness
            if what == LinuxEventMonitor.ProcEvent.FORK.value:
                ppid, ptgid, cpid, ctgid = struct.unpack("=IIII", data[:16])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.FORK]:
                    callback(ppid=ppid, ptgid=ptgid, cpid=cpid, ctgid=ctgid,
                             processes=dict(parent=self._get_process(ppid), child=self._get_process(cpid)))

            elif what == LinuxEventMonitor.ProcEvent.COMM:
                pid, tgid, name = struct.unpack("=II16s", data)
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.COMM]:
                    callback(pid=pid, tgid=tgid, name=name, process=self._get_process(pid))

            elif what == LinuxEventMonitor.ProcEvent.CORE_DUMP.value:
                pid, tgid = struct.unpack("=II", data[:8])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.CORE_DUMP]:
                    callback(pid=pid, tgid=tgid, process=self._get_process(pid))

            elif what == LinuxEventMonitor.ProcEvent.PTRACE.value:
                pid, tgid, tpid, ttgid = struct.unpack("=IIII", data[:16])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.PTRACE]:
                    callback(pid=pid, tgid=tgid, tpid=tpid, ttgid=ttgid, process=dict(
                        tracer=self._get_process(pid), traced=self._get_process(tpid)))

            elif what == LinuxEventMonitor.ProcEvent.EXIT.value:
                pid, tgid, exit_code, exit_signal = struct.unpack("=IILL", data[:16])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.EXIT]:
                    callback(pid=pid, tgid=tgid, exit_code=exit_code, exit_signal=exit_signal,
                             process=self._get_process(pid))
                self.processes.pop(pid, None)

            elif what == LinuxEventMonitor.ProcEvent.UID.value:
                pid, tgid, ruid, euid = struct.unpack("=IILL", data[:16])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.UID]:
                    callback(pid=pid, tgid=tgid, ruid=ruid, euid=euid, process=self._get_process(pid))

            elif what == LinuxEventMonitor.ProcEvent.GID.value:
                pid, tgid, rgid, egid = struct.unpack("=IILL", data[:16])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.GID]:
                    callback(pid=pid, tgid=tgid, ruid=rgid, euid=egid, process=self._get_process(pid))

            elif what == LinuxEventMonitor.ProcEvent.SID.value:
                pid, tgid = struct.unpack("=II", data[:8])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.SID]:
                    callback(pid=pid, tgid=tgid, process=self._get_process(pid))

            elif what == LinuxEventMonitor.ProcEvent.EXEC.value:
                pid, tgid = struct.unpack("=II", data[:8])
                for callback in self.callbacks[LinuxEventMonitor.ProcEvent.EXEC]:
                    callback(pid=pid, tgid=tgid, process=self._get_process(pid))

    def add_callback(self, event: Event, callback: callable):
        """Add a callback"""
        try:
            for proc_event in LinuxEventMonitor.EVENTS_MAP[event]:
                self.callbacks[proc_event].append(callback)
            logging.info("Added callback for event %s", event)
        except KeyError:
            pass

    def stop(self):
        logging.debug("Stopping LinuxEventMonitor")
        self.sock.close()


def main():
    # Simple testing code
    import time

    run_time = 5

    def make_test_callback(event: LinuxEventMonitor.ProcEvent):
        def exec_callback(**kwargs):
            print(event)
            for k, v in kwargs.items():
                print("\t{} => {}".format(k, v))

        return exec_callback

    print("Listening to events for", run_time, "seconds")
    mon = LinuxEventMonitor()
    for e in LinuxEventMonitor.EVENTS_MAP:
        mon.add_callback(e, make_test_callback(e))
    t = threading.Thread(target=mon.run)
    t.start()
    time.sleep(run_time)
    mon.stop()
    t.join()


if __name__ == '__main__':
    main()
