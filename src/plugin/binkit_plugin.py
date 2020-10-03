import os
import idautils
import idaapi
import idc
import thread
import traceback

from binkit.viewer import *
from binkit.service import *

class MenuHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.viewer_sequence = 0

    def load_results(self):
        filename = get_filename()
        if filename and os.path.isfile(filename):
            viewer = Viewer(filename)
            form_name = "Function Matches-%d" % self.viewer_sequence
            self.viewer_sequence += 1
            viewer.show_functions_match_viewer(form_name)
            idaapi.set_dock_pos(form_name, "Functions window", idaapi.DP_TAB)

    def activate(self, ctx):
        print('activate: ' + str(ctx))
        self.load_results()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class BinkitPlugin(idaapi.plugin_t):
    wanted_name = "Binkit"    
    wanted_hotkey = "Alt-F12"
    comment = "Binkit Plugin For IDA"
    help = "Use this plugin to load diffing result files (*.json)..."
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        self.get_connection_filename()
        thread.start_new_thread(start_binkit_server, (self.connection_filename,))

        action_desc = idaapi.action_desc_t('my:action', 'Load Results', MenuHandler(), 'Ctrl+H', 'Load Results', 199)
        idaapi.register_action(action_desc)        
        idaapi.attach_action_to_menu('Edit/Other/', 'my:action', idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def get_connection_filename(self):
        binkit_profile = os.path.join(os.environ['USERPROFILE'], '.binkit')
        if not os.path.isdir(binkit_profile):
            try:
                os.makedirs(binkit_profile)
            except:
                traceback.print_exc()
        md5 = idc.GetInputMD5().lower()
        self.connection_filename = os.path.join(binkit_profile, "%s-%d.port" % (md5, os.getpid()))

    def run(self, arg):
        pass

    def term(self):
        if os.path.isfile(self.connection_filename):
            try:
                print("Removing %s" % self.connection_filename)
                os.remove(self.connection_filename)
            except:
                traceback.print_exc()

def PLUGIN_ENTRY():
    return BinkitPlugin()
