# Installation

---
## rpyc

* binkit depends on rpyc for RPC. Please install it using following commands.

```
pip install rpyc
```

---
## binkit IDA Plugin

* You can run following IDAPython script to download and install binkit IDA Plugin
   - [Download](Scripts/install_binkit_plugin.py)

```
import os
import urllib2
plugins_folder = os.path.join(idaapi.get_user_idadir(), "plugins")
if not os.path.isdir(plugins_folder):
    os.makedirs(plugins_folder)
for filename in ('binkit.dll', 'binkit64.dll'):
   url = 'https://github.com/ohjeongwook/binkit/releases/download/v0.1/' + filename
   local_filename = os.path.join(plugins_folder, filename)
   print('Downloading %s -> %s' % (url, local_filename))
   response = urllib2.urlopen(url)
   with open(local_filename, 'wb') as fd:
      fd.write(response.read())
```

---
### Plugin folder

```
%USERPROFILE%\AppData\Roaming\Hex-Rays\IDA Pro\plugins
```
