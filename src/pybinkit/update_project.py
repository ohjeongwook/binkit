import os
import xml.etree.ElementTree
from winreg import *
import traceback
import itertools
import re
import pprint

class VCXProjParser:
    def __init__(self, project_filename = 'pybinkit.vcxproj'):
        root = xml.etree.ElementTree.parse(project_filename).getroot()
        xmlns = r'{http://schemas.microsoft.com/developer/msbuild/2003}'

        for property_group in root.findall(xmlns + 'PropertyGroup'):
            if not 'Condition' in property_group.attrib:
                continue

            include_paths = property_group.findall(xmlns + 'IncludePath')

            if len(include_paths) <= 0:
                continue

            print('='*80)    
            print(property_group.attrib['Condition'])

            for include_path in include_paths:
                print('\t'+'-'*80)
                print('\t'+include_path.text)

        for item_definition_group in root.findall(xmlns + 'ItemDefinitionGroup'):
            if not 'Condition' in item_definition_group.attrib:
                continue

            additional_library_directories = item_definition_group.findall(xmlns + 'Link' + '/' + xmlns + 'AdditionalLibraryDirectories')

            if len(additional_library_directories) <= 0:
                continue

            print('='*80)    
            print(item_definition_group.attrib['Condition'])

            for additional_library_directory in additional_library_directories:
                print('\t'+'-'*80)
                print('\t'+ additional_library_directory.text)
                additional_library_directory_list = additional_library_directory.text.split(';')
                additional_library_directory_list.sort()

                pprint.pprint(additional_library_directory_list)

class PythonInstallPath:
    def __init__(self):
        self.instllation_list = []
        self.query_keys(HKEY_LOCAL_MACHINE)
        self.query_keys(HKEY_CURRENT_USER)

        python2_max_version = 0
        python2_attribute = {}

        python3_max_version = 0
        python3_attribute = {}
        for attributes in self.instllation_list:
            if attributes['version'] >= 3.0:
                if attributes['version'] > python3_max_version:
                    python3_max_version = attributes['version']
                    python3_attribute = attributes

            elif attributes['version'] >= 2.0:
                if attributes['version'] > python2_max_version:
                    python2_max_version = attributes['version']
                    python2_attribute = attributes

        if len(python2_attribute) > 0:
            print('-'*80)
            print(python2_attribute['path'])
            print(python2_attribute['dll'][-1])

            self.set_env('PYTHON2_PATH', python2_attribute['path'])
            self.set_env('PYTHON2_LIB_NAME', python2_attribute['dll'][-1])

        if len(python3_attribute) > 0:
            print('-'*80)
            print(python3_attribute['path'])
            print(python3_attribute['dll'][-1])

            self.set_env('PYTHON3_PATH', python3_attribute['path'])
            self.set_env('PYTHON3_LIB_NAME', python3_attribute['dll'][-1])            

    def check_python_files(self, path):
        python_header = os.path.join(path, 'include\\Python.h')
        if not os.path.isfile(python_header):
            return []

        python_libs = os.path.join(path, 'libs')

        dll_names = []
        for filename in os.listdir(python_libs):
            if re.search('^python[0-9]{2}.lib', filename):
                dll_names.append(filename)

        if len(dll_names) <= 0:
            return []

        return dll_names

    def query_keys(self, root_key_value):
        root_key = ConnectRegistry(None, root_key_value)
        for python_core_path in (r"SOFTWARE\Python\PythonCore", r"SOFTWARE\Wow6432Node\Python\PythonCore"):
            self.query_python_core_keys(root_key, python_core_path)

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
                #traceback.print_exc()
                break

        for version_key_str in version_key_str_list:
            path_key_str = python_core_path + "\\" + version_key_str + "\\InstallPath"
            try:
                path_key = OpenKey(root_key, path_key_str)
                path = QueryValue(path_key, '')
                dll_names = self.check_python_files(path)

                if len(dll_names) > 0:
                    self.instllation_list.append({'version': float(version_key_str), 'path': path, 'dll': dll_names})
            except WindowsError:
                pass

    def set_env(self, name, value):
        print('* set_env: ', name, value)
        key = OpenKey(HKEY_CURRENT_USER, 'Environment', 0, KEY_ALL_ACCESS)
        SetValueEx(key, name, 0, REG_EXPAND_SZ, value)
        CloseKey(key)
        
if __name__ == '__main__':
    python_path = PythonInstallPath()
    #vcxproj_parser = VCXProjParser('pybinkit.vcxproj')
