import os
import urllib2

try:
    idadir = idaapi.get_user_idadir()
except:
    idadir = os.path.join(os.environ['USERPROFILE'], r'AppData\Roaming\Hex-Rays\IDA Pro')

plugins_folder = os.path.join(idadir, "plugins")

if not os.path.isdir(plugins_folder):
    os.makedirs(plugins_folder)
for filename in ('binkit.dll', 'binkit64.dll'):
   url = 'https://github.com/ohjeongwook/binkit/releases/download/v0.1/' + filename
   local_filename = os.path.join(plugins_folder, filename)
   print('Downloading %s -> %s' % (url, local_filename))
   response = urllib2.urlopen(url)
   with open(local_filename, 'wb') as fd:
      fd.write(response.read())