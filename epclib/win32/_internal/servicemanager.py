"""
servicemanager.py : Manage Services

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
import win32service

class Win32ServiceManager(object):
    """
    Manages Win32Services
    """
    def __init__(self):
        self.hscm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CREATE_SERVICE)
        self.__managed_services = {}

    def get_service(self, name):
        """
        Returns the handle to a service
        """
        hsvc = self.__managed_services.get(name)
        if not hsvc:
            hsvc = win32service.OpenService(self.hscm,
                                            win32service.FLAGS.name,
                                            win32service.SERVICE_ALL_ACCESS)
            self.__managed_services[name] = hsvc
        return hsvc

    def load_driver(self, name, path):
        """
        Load a driver

        Returns:
            handle to the driver
        """
        try:
            hsvc = win32service.CreateService(
                self.hscm, name, name,
                win32service.SERVICE_ALL_ACCESS,
                win32service.SERVICE_KERNEL_DRIVER,
                win32service.SERVICE_DEMAND_START,
                win32service.SERVICE_ERROR_IGNORE,
                path,
                None, 0, None, None, None)
            self.__managed_services[name] = hsvc
        except win32service.error:
            hsvc = self.get_service(name)
        return hsvc             

    def delete_service(self, name):
        """
        Stops and delete a service
        """
        self.stop_service(name)
        hsvc = self.get_service(name)
        del self.__managed_services[name]
        win32service.DeleteService(hsvc)
        win32service.CloseServiceHandle(hsvc)

    def stop_service(self, name):
        """
        Stops a service
        """
        try:
            hsvc = self.get_service(name)
            win32service.ControlService(hsvc, win32service.SERVICE_CONTROL_STOP)
            return True
        except win32service.error:
            return False

    def start_service(self, name):
        """
        Starts a service
        """
        try:
            hsvc = self.get_service(name)
            win32service.StartService(hsvc, [])
            return True
        except win32service.error:
            return False

scm = Win32ServiceManager()
