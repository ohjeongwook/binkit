import os
import traceback
import rpyc

class Syncer:
    def __init__(self, md5):
        for port in range(18861, 18861 + 5, 1):
            try:
                print('rpyc.connect: %d' % port)
                self.connection = rpyc.connect("127.0.0.1", port)
                self.connection._config['sync_request_timeout'] = 1
            except:
                self.connection = None
                continue

            if self.connection.root.get_pid() == os.getpid():
                self.connection = None
                continue

            if self.connection.root.get_md5() == md5:
                print('found %s at %d' % (md5, port))
                break
                
            self.connection = None
            
    def jumpto(self, address):
        if self.connection != None:
            self.connection.root.jumpto(address)
        
if __name__ == '__main__':
    syncer = Syncer('b8e114bf915b74e9e64aba6888c46cb6')
    syncer.jumpto(0x6C84C2A0)

    syncer = Syncer('b4be1f81a7f4521b2bc2abf72785493d')
    syncer.jumpto(0x00433392)