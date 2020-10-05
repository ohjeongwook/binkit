import os
import idautils
import idaapi
import idc
import thread
import traceback
import threading

from binkit.viewer import *
from binkit.service import *
import binkit.binaries
import binkit.python

class LoadResultsHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.viewer_sequence = 0

    def get_filename(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(None, "QFileDialog.getOpenFileName()", "","All Files (*);;JSON (*.json)", options=options)
        return filename

    def load_results(self):
        filename = self.get_filename()
        if filename and os.path.isfile(filename):
            viewer = Viewer(filename)
            form_name = "Function Matches-%d" % self.viewer_sequence
            self.viewer_sequence += 1
            viewer.show_functions_match_viewer(form_name)
            idaapi.set_dock_pos(form_name, "Functions window", idaapi.DP_TAB)

    def activate(self, ctx):
        self.load_results()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class DiffHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.viewer_sequence = 0
        self.use_process = True

    def get_filename(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        filename, _ = QtWidgets.QFileDialog.getOpenFileName(None, "QFileDialog.getOpenFileName()", "","All Files (*);;DB (*.db)", options=options)
        return filename

    def match_thread(self, src_filename, target_filename):
        print('match_thread:', src_filename, target_filename)
        binary_matcher = binkit.binaries.Matcher(filenames = (src_filename, target_filename))
        binary_matcher.match("output-diff2.json")

    def activate(self, ctx):
        target_filename = self.get_filename()
        if target_filename and os.path.isfile(target_filename):
            src_filename = os.path.splitext(idc.get_idb_path())[0] + '.db'
            print('Diffing: %s - %s' % (src_filename, target_filename))

            if self.use_process:
                launcher = binkit.python.Launcher()
                script_name = os.path.splitext(binkit.binaries.__file__)[0] + '.py'
                parameters = [script_name, '-o', 'output.json', src_filename, target_filename]
                print(parameters)
                launcher.run(parameters)
            else:
                t = threading.Thread(target=self.match_thread, args=(src_filename, target_filename))
                t.start()

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

        action_desc = idaapi.action_desc_t('my:action', 'Load Results', LoadResultsHandler(), 'Ctrl+H', 'Load Results', 199)
        idaapi.register_action(action_desc)        
        idaapi.attach_action_to_menu('Edit/Other/', 'my:action', idaapi.SETMENU_APP)

        action_desc = idaapi.action_desc_t('my:diff', 'Diff Results', DiffHandler(), 'Ctrl+D', 'Diff Results', 199)
        idaapi.register_action(action_desc)        
        idaapi.attach_action_to_menu('Edit/Other/', 'my:diff', idaapi.SETMENU_APP)

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
