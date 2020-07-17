import os
import shutil

try:
    idadir = idaapi.get_user_idadir()
except:
    idadir = os.path.join(os.environ['USERPROFILE'], r'AppData\Roaming\Hex-Rays\IDA Pro')

plugins_folder = os.path.join(idadir, "plugins")

if not os.path.isdir(plugins_folder):
    os.makedirs(plugins_folder)

for filename in (r'..\plugin\x64\IDA32-Debug\binkit.dll', r'..\plugin\x64\IDA64-Debug\binkit64.dll'):
    base_filename = os.path.basename(filename)
    plugin_filename = os.path.join(plugins_folder, base_filename)
    print('Copying %s -> %s' % (filename, plugin_filename))
    shutil.copyfile(filename, plugin_filename)
