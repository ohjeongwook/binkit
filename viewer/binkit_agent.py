import os
import idautils
import idaapi
import idc
import traceback
import rpyc
from rpyc.utils.server import ThreadedServer

from binkit.viewer import *
from binkit.threadtool import *

class BinKitService(rpyc.Service):
    def on_connect(self, conn):
        self.ida = IDA()

    def get_pid(self):
        return os.getpid()
    
    def jumpto(self, address):
        print('jumpto: %x' % address)
        self.ida.jumpto(address)
        
    def get_md5(self):
        return self.ida.get_md5()

def start_binkit_server():
    port = 18861
    while 1:
        try:
            t = ThreadedServer(BinKitService(), port = port, protocol_config = {
                'allow_public_attrs': True,
            })
            print('Listening on %d\n' % port)
            t.start()
            break
        except:
            port += 1
            traceback.print_exc()

class BinkitPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Binkit Sync Agent"

    wanted_name = "Binkit Agent Plugin"
    wanted_hotkey = "Alt-F6"
    help = "TestPlugin..."

    def init(self): 
        idaapi.msg("init\n")
        thread.start_new_thread(start_binkit_server, ())  
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run\n")
        viewer = Viewer(get_filename())
        viewer.show_functions_match_viewer()
        viewer.set_basic_blocks_color(0xCCFFFF, 0xCC00CC)

    def term(self):
        idaapi.msg("term\n")

def PLUGIN_ENTRY():
    return BinkitPlugin()
