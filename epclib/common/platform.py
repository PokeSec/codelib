"""
platform.py : Platform information

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
import enum
import platform
from pathlib import Path
from typing import Optional, Iterable

import arrow
import psutil

from epc.common.platform import PlatformData
from epc.common.settings import Config


class PlatformInfo(object):
    """Get Platform information"""

    class Level(enum.IntEnum):
        """
        Level of details:
        basic -- only the basic information
        advanced -- more advanced and time-consuming information
        full -- complete information, may consume a lot of time
        """
        basic = 0
        advanced = 1
        full = 2

    def __init__(self):
        self.__data = {}
        self.level = PlatformInfo.Level.basic

    def get_data(self, level: Level, types: Iterable[str] = None, norefresh: bool = False) -> Optional[dict]:
        """
        Get the platform information data

        Arguments:
        level -- instance of PlatformInfo.Level
        types -- type of data to gather
        norefresh -- use cached information if available
        """
        data = self.__data.get(level)
        if data and norefresh:
            return data

        self.level = level
        self.__data[level] = {}

        # Retrieve all data getters from self
        prefix = "_{}__get_".format(type(self).__name__)
        getters = {f.split(prefix, 1)[1]: getattr(self, f) for f in dir(self) if callable(getattr(self, f))
                   and f.startswith(prefix)}

        if types:  # Only call specified data getters
            getters = {k: v for k, v in getters.items() if k in types}

        for name, func in getters.items():
            try:
                self.__data[level][name] = func()
            except NotImplementedError:
                continue

        return self.__data.get(level, None)

    def __get_platform(self):
        """Retrieve platform information"""
        return PlatformData().get_data()

    def __get_cpu(self):
        """Retrieve CPU information"""
        data = {
            'count': psutil.cpu_count(),
            'load': psutil.cpu_percent(),
        }
        if self.level > 2:
            data['load_detailed'] = psutil.cpu_percent(percpu=True),
        return data

    def __get_memory(self):
        """Retrieve memory information"""
        return psutil.virtual_memory()._asdict()

    def __get_disk(self):
        """Retrieve disk information"""
        partitions = psutil.disk_partitions()
        data = {
            'partitions': [x._asdict() for x in partitions]
        }
        if self.level > 2:
            disk_usage = {}
            for part in partitions:
                disk_usage[part.mountpoint] = psutil.disk_usage(part.mountpoint)._asdict()
            data['usage'] = disk_usage
        return data

    def __get_network(self):
        """Retrieve network information"""
        addrs = {}

        for ifname, data in psutil.net_if_addrs().items():
            addrs[ifname] = []
            for addr in data:
                addrs[ifname].append(addr._asdict())

        data = {
            'addrs': addrs
        }

        if self.level > 1:
            stats = {}
            for ifname, stat in psutil.net_if_stats().items():
                stats[ifname] = stat._asdict()
            data['stats'] = stats
        return data

    def __get_boot_time(self):
        """Retrieve system boot time"""
        return dict(
            boot_time=arrow.get(psutil.boot_time()).isoformat()
        )

    def __get_user(self):
        """Retrieve users information"""
        data = {
            'list': [x._asdict() for x in psutil.users()]
        }
        return data

    def __get_process(self):
        """Retrieve processes information"""
        if self.level > 2:
            attrs = []
        else:
            attrs = ['pid', 'name', 'status', 'username']
        return [x.as_dict(attrs=attrs) for x in psutil.process_iter()]

    def __get_winservice(self):
        """Retrieve windows service information"""
        if Config().PLATFORM != 'win32':
            raise NotImplementedError("Cannot get Windows service information on a non-win32 system")
        data = []
        for srv in psutil.win_service_iter():
            data.append({
                'name': srv.name(),
                'binpath': srv.binpath(),
                'username': srv.username(),
                'start_type': srv.start_type(),
                'status': srv.status(),
                'pid': srv.pid()
            })
        return data

    def __get_software(self):
        """Retrieve installed software information"""
        data = []
        if Config().PLATFORM == 'android':
            import jnius
            EPCService = jnius.autoclass(Config().JAVA_SERVICE)
            from epc.android.utils import PythonListIterator
            pm = EPCService.mService.getPackageManager()
            installed = pm.getInstalledPackages(0)
            for package in PythonListIterator(installed):
                data.append(dict(
                    name=package.packageName,
                    installTime=arrow.get(package.firstInstallTime / 1000).isoformat(),
                    updateTime=arrow.get(package.lastUpdateTime / 1000).isoformat(),
                    version=package.versionName
                ))

        elif Config().PLATFORM == 'unix':
            if platform.system().lower().startswith("darwin"):
                import sh
                import plistlib
                xml = sh.system_profiler("SPApplicationsDataType", "-xml")
                plist = plistlib.loads(xml.stdout)
                for package in plist[0]["_items"]:
                    pkg_data = {}
                    if "_name" in package:
                        pkg_data["name"] = package["_name"]
                    else:
                        continue
                    if "version" in package:
                        pkg_data["version"] = package["version"]
                    if "lastModified" in package:
                        pkg_data["installTime"] = package["lastModified"].isoformat()
                        pkg_data["updateTime"] = pkg_data["installTime"]
                    data.append(pkg_data)
            else:
                import distro
                import sh
                distrib = distro.linux_distribution(full_distribution_name=False)
                if distrib in ("rhel", "centos", "sles"):
                    for package in sh.rpm('-qa', queryformat="%{NAME} %{VERSION}%{RELEASE} %{INSTALLTIME}\n",
                                          _iter=True):
                        name, version, installTime = package.split()
                        data.append(dict(
                            name=name,
                            version=version,
                            installTime=arrow.get(installTime).isoformat()
                        ))
                elif distrib in ("debian", "ubuntu"):
                    for package in sh.Command('dpkg-query')('-W', f='${binary:Package} ${Version}\n', _iter=True):
                        pkg_data = {}
                        name, version = package.split()
                        pkg_data['name'], pkg_data['version'] = name, version
                        infolist = Path('/var/lib/dpkg/info') / "{}.list".format(name)
                        if infolist.exists():
                            pkg_data['installTime'] = arrow.get(infolist.stat().st_ctime).isoformat()
                            pkg_data['updateTime'] = arrow.get(infolist.stat().st_atime).isoformat()
                        data.append(pkg_data)

        elif Config().PLATFORM == 'win32':
            from epclib.registry.utils import list_uninstall
            for package in list_uninstall():
                pkg_data = {}
                if "DisplayName" in package:
                    pkg_data["name"] = package["DisplayName"]
                else:
                    continue
                if "DisplayVersion" in package:
                    pkg_data["version"] = package["DisplayVersion"]
                if "InstallDate" in package:
                    pkg_data["installTime"] = arrow.get(package["InstallDate"], "YYYYMMDD").isoformat()
                    pkg_data["updateTime"] = pkg_data["installTime"]
                data.append(pkg_data)

        return data
