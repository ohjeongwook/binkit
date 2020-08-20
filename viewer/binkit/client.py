import os
import traceback
import glob
import json
import rpyc

class Syncer:
    def __init__(self, md5):
        for port in self.get_ports(md5):
            try:
                print("Connecting to %d" % port)
                self.connection = rpyc.connect("127.0.0.1", port)
                self.connection._config['sync_request_timeout'] = 1
            except:
                self.connection = None
                continue

            if self.connection.root.get_pid() == os.getpid():
                self.connection = None
                continue

            if self.connection.root.get_md5() == md5:
                break

    def get_ports(self, md5):
        pattern = os.path.join(os.environ['USERPROFILE'], '.binkit\\%s-*.port' % md5)
        ports = []
        for filename in glob.glob(pattern):
            with open(filename, "r") as fd:
                configuration = json.load(fd)
                print(configuration)
                if 'port' in configuration:
                    ports.append(configuration['port'])
        return ports
            
    def jumpto(self, address):
        if self.connection != None:
            self.connection.root.jumpto(address)
        
if __name__ == '__main__':
    syncer = Syncer('b8e114bf915b74e9e64aba6888c46cb6')
    syncer.jumpto(0x6C84C2A0)

    syncer = Syncer('b4be1f81a7f4521b2bc2abf72785493d')
    syncer.jumpto(0x00433392)