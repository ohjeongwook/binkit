import os
import json

import idaapi
import idc
import ida_bytes
from PyQt5 import QtGui, QtCore, QtWidgets

from function_match import *
from functions_match_viewer import *

class Viewer:
    def __init__(self, filename):
        self.match_results = []
        if os.path.isfile(filename):
            self.function_match_tool = FunctionMatchTool(filename = filename)

        md5 = idc.GetInputMD5().lower()
        if md5 == self.function_match_tool.get_md5('source'):
            self.self_name = 'source'
            self.peer_name = 'target'
        elif md5 == self.function_match_tool.get_md5('target'):
            self.self_name = 'target'
            self.peer_name = 'source'
        else:
            self.self_name = 'source'
            self.peer_name = 'target'

    def show_functions_match_viewer(self, form_name):
        form = FunctionsMatchViewer()
        form.Show(form_name)
        form.add_items(self.function_match_tool.select_by_score(), self.self_name, self.peer_name, self.function_match_tool.get_md5(self.peer_name), 0x00ff00, 0x0000ff)

def get_filename():
    options = QtWidgets.QFileDialog.Options()
    options |= QtWidgets.QFileDialog.DontUseNativeDialog
    filename, _ = QtWidgets.QFileDialog.getOpenFileName(None, "QFileDialog.getOpenFileName()", "","All Files (*);;JSON (*.json)", options=options)
    return filename

if __name__ == '__main__':
    viewer = Viewer(get_filename())
    viewer.show_functions_match_viewer()
    viewer.set_basic_blocks_color(0xCCFFFF, 0xCC00CC)
    idaapi.set_dock_pos("Function Matches", "Functions window", idaapi.DP_TAB)
