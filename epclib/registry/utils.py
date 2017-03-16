"""
utils.py: Registry utils

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
import winreg
from typing import List


def enum_keys(key):
    i = 0
    while True:
        try:
            subkey = winreg.EnumKey(key, i)
            yield subkey
            i += 1
        except OSError:
            break


def regkey_to_dict(key) -> dict:
    result = {}
    i = 0
    while True:
        try:
            value = winreg.EnumValue(key, i)
            result[value[0]] = value[1]
            i += 1
        except OSError:
            break
    return result


def list_uninstall() -> List[dict]:
    result = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall") as key:
        for subkey_name in enum_keys(key):
            with winreg.OpenKey(key, subkey_name) as subkey:
                result.append(regkey_to_dict(subkey))
    return result
