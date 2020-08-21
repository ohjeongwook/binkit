import os
import urllib2
import zipfile

try:
    idadir = idaapi.get_user_idadir()
except:
    idadir = os.path.join(os.environ['USERPROFILE'], r'AppData\Roaming\Hex-Rays\IDA Pro')

plugins_folder = os.path.join(idadir, "plugins")

if not os.path.isdir(plugins_folder):
    os.makedirs(plugins_folder)

filename = 'plugins.zip'
url = 'https://github.com/ohjeongwook/binkit/releases/download/v0.2/' + filename
local_filename = os.path.join(plugins_folder, filename)
print('Downloading %s -> %s' % (url, local_filename))
response = urllib2.urlopen(url)
with open(local_filename, 'wb') as fd:
    fd.write(response.read())

print('Extracting %s -> %s' % (local_filename, plugins_folder))
with zipfile.ZipFile(local_filename, 'r') as zip_ref:
    zip_ref.extractall(plugins_folder)

print('Removing %s' % (local_filename))
os.remove(local_filename)
