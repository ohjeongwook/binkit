import idaapi
import ida_bytes
import json
from functions_match_viewer import *
from PyQt5 import QtGui, QtCore, QtWidgets

class Viewer:
    def __init__(self, filename):
        with open(filename, 'r') as fd:
            self.match_results = json.load(fd)

        md5 = idc.GetInputMD5().lower()
        if md5 == self.match_results['binaries']['source']['md5']:
            self.self_name = 'source'
            self.peer_name = 'target'
        elif md5 == self.match_results['binaries']['target']['md5']:
            self.self_name = 'target'
            self.peer_name = 'source'
        else:
            self.self_name = 'source'
            self.peer_name = 'target'

        self.count_blocks()

    def count_blocks(self):
        for function_match in self.match_results['function_matches']:
            matched_block_counts = 0
            self_unidentified_block_counts = 0
            peer_unidentified_block_counts = 0

            if 'matches' in function_match:
                matched_block_counts = len(function_match['matches']) * 2

            if 'unidentified_blocks' in function_match:
                self_unidentified_block_counts += len(function_match['unidentified_blocks'][self.self_name+'s'])
                peer_unidentified_block_counts += len(function_match['unidentified_blocks'][self.peer_name+'s'])
                
            function_match['matched_block_counts'] = matched_block_counts
            function_match['self_unidentified_block_counts'] = self_unidentified_block_counts
            function_match['peer_unidentified_block_counts'] = peer_unidentified_block_counts

    def show_functions_match_viewer(self, form_name):
        idaapi.msg("show_functions_match_viewer\n")
        form = FunctionsMatchViewer()
        form.Show(form_name)
        
        for function_match in self.match_results['function_matches']:
            form.add_item(function_match[self.self_name],
                          function_match[self.peer_name],
                          function_match['matched_block_counts'],
                          function_match['self_unidentified_block_counts'],
                          function_match['peer_unidentified_block_counts'],
                          self.match_results['binaries'][self.peer_name]['md5']
                    )

    def color(self, start, end, color):
        address = idaapi.get_imagebase() + start
        while address < idaapi.get_imagebase() + end:
            idaapi.set_item_color(address, color)
            address += ida_bytes.get_item_size(address)
                
    def set_basic_blocks_color(self, color, color_for_unidentified):
        for function_match in self.match_results['function_matches']:
            if 'matches' in function_match:
                for match_data in function_match['matches']:
                    self.color(match_data[self.self_name], match_data[self.self_name+'_end'], color)

            if 'unidentified_blocks' in function_match:
                for basic_block in function_match['unidentified_blocks'][self.self_name+'s']:
                    self.color(basic_block['start'], basic_block['end'], color_for_unidentified)

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
