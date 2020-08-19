import os
import idautils
import idaapi
import idc
import traceback
from threadtool import *
import rpyc
from rpyc.utils.server import ThreadedServer

class MyService(rpyc.Service):
    def on_connect(self, conn):
        self.ida = IDA()

    def get_pid(self):
        return os.getpid()
    
    def jumpto(self, address):
        print('jumpto: %x' % address)
        self.ida.jumpto(address)
        
    def get_md5(self):
        return self.ida.get_md5()

def run():
    port = 18861
    while 1:
        try:
            t = ThreadedServer(MyService(), port = port, protocol_config = {
                'allow_public_attrs': True,
            })
            print('Listening on %d\n' % port)
            t.start()
            break
        except:
            port += 1
            traceback.print_exc()
            
    print("run end\n")

class BinkitPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Binkit Sync Agent"

    wanted_name = "Binkit Agent Plugin"
    wanted_hotkey = "Alt-F6"
    help = "TestPlugin..."

    def init(self): 
        idaapi.msg("init\n")
        thread.start_new_thread(run, ())  
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run\n")
    
    def term(self):
        idaapi.msg("term\n")

def PLUGIN_ENTRY():
   return BinkitPlugin()
