import os
from winreg import *
import traceback
import itertools
import re
import pprint
import subprocess

class Launcher:
    def __init__(self):
        self.installations = []
        self.python_attributes = {2: {}, 3: {}}

        self.query_keys(HKEY_LOCAL_MACHINE)
        self.query_keys(HKEY_CURRENT_USER)

        python2_max_version = 0
        python3_max_version = 0
        for attributes in self.installations:
            if attributes['version'] >= 3.0:
                if attributes['version'] > python3_max_version:
                    python3_max_version = attributes['version']
                    self.python_attributes[3] = attributes

            elif attributes['version'] >= 2.0:
                if attributes['version'] > python2_max_version:
                    python2_max_version = attributes['version']
                    self.python_attributes[2] = attributes

    def query_python_core_keys(self, root_key, python_core_path):
        try:
            python_core_key = OpenKey(root_key, python_core_path)
        except:
            return

        version_key_str_list = []
        for i in itertools.count():
            try:
                version_key_str_list.append(EnumKey(python_core_key, i))
            except WindowsError:
                break

        for version_key_str in version_key_str_list:
            path_key_str = python_core_path + "\\" + version_key_str + "\\InstallPath"
            try:
                path_key = OpenKey(root_key, path_key_str)
                path = QueryValue(path_key, '')
                python_exe_path = ''
                for current_python_exe_path in (os.path.join(path, 'python.exe'), os.path.join(path, 'python3.exe')):
                    print('current_python_exe_path: ' + current_python_exe_path)
                    if os.path.isfile(current_python_exe_path):
                        python_exe_path = current_python_exe_path
                        break

                if python_exe_path:
                    self.installations.append({'version': float(version_key_str), 'path': path, 'python_exe_path': python_exe_path})
            except WindowsError:
                pass

    def query_keys(self, root_key_value):
        root_key = ConnectRegistry(None, root_key_value)
        for python_core_path in (r"SOFTWARE\Python\PythonCore", r"SOFTWARE\Wow6432Node\Python\PythonCore"):
            self.query_python_core_keys(root_key, python_core_path)

    def run(self, args, version = 2):
        if version in self.python_attributes:
            params = [self.python_attributes[version]['python_exe_path']] + args
            subprocess.Popen(params)

if __name__ == '__main__':
    import sys
    launcher = Launcher()
    launcher.run(sys.argv[1:])
