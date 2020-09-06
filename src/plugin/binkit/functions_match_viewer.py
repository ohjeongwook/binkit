import thread
import traceback
import idaapi
import idc
import ida_bytes
from PyQt5 import QtGui, QtCore, QtWidgets
from client import *
from Queue import Queue
from threading import Thread

def sync_worker(queue):
    syncers = {}
    while True:
        commands = queue.get()
        queue.task_done()
        if not commands['md5'] in syncers or syncers[commands['md5']] == None:
            syncers[commands['md5']] = IDASessions.connect(commands['md5'])

        connection = syncers[commands['md5']]
        try:
            if connection:
                connection.root.run_commands(commands['list'])
        except:
            traceback.print_exc()
            del syncers[commands['md5']]

class FunctionsMatchViewer(idaapi.PluginForm):
    def color_block(self, start, end, color):
        address = idaapi.get_imagebase() + start
        while address < idaapi.get_imagebase() + end:
            idaapi.set_item_color(address, color)
            address += ida_bytes.get_item_size(address)

    def set_basic_blocks_color(self):
        for function_match in self.match_results['function_matches']:
            self.matched_block_color_function_match(function_match)
    
    def tree_double_clicked_handler(self, item, column_no):
        idaapi.jumpto(idaapi.get_imagebase() + item.function_match[item.self_name])
        commands = {'md5': item.peer_md5, 'list': []}
        commands['list'].append(({'name': 'jumpto', 'address': item.function_match[item.peer_name]}))
        if 'matches' in item.function_match:
            for match_data in item.function_match['matches']:
                self.color_block(match_data[self.self_name], match_data[self.self_name+'_end'], self.matched_block_color)
                commands['list'].append({'name': 'color_block', 'start': match_data[self.peer_name], 'end': match_data[self.peer_name+'_end'], 'color': self.matched_block_color})

        if 'unidentified_blocks' in item.function_match:
            for basic_block in item.function_match['unidentified_blocks'][self.self_name+'s']:
                self.color_block(basic_block['start'], basic_block['end'], self.unidentified_block_color)
                commands['list'].append({'name': 'color_block', 'start': match_data[self.peer_name], 'end': match_data[self.peer_name+'_end'], 'color': self.unidentified_block_color})
        item.queue.put(commands)

    def add_items(self, match_results, self_name, peer_name, peer_md5, color, color_for_unidentified):
        self.matched_block_color = color
        self.unidentified_block_color = color_for_unidentified
        self.match_results = match_results
        self.self_name = self_name
        self.peer_name = peer_name
        self.peer_md5 = peer_md5

        for function_match in self.match_results['function_matches']:
            self.add_item(function_match)

    def count_blocks(self, function_match):
        matched_block_counts = 0
        self_unidentified_block_counts = 0
        peer_unidentified_block_counts = 0

        if 'matches' in function_match:
            matched_block_counts = len(function_match['matches']) * 2

        if 'unidentified_blocks' in function_match:
            self_unidentified_block_counts += len(function_match['unidentified_blocks'][self.self_name+'s'])
            peer_unidentified_block_counts += len(function_match['unidentified_blocks'][self.peer_name+'s'])

        counts = {}
        counts['matched_block_counts'] = matched_block_counts
        counts['self_unidentified_block_counts'] = self_unidentified_block_counts
        counts['peer_unidentified_block_counts'] = peer_unidentified_block_counts
        return counts

    def add_item(self, function_match):
        item = QtWidgets.QTreeWidgetItem(self.tree)
        item.function_match = function_match
        item.self_name = self.self_name
        item.peer_name = self.peer_name
        item.peer_md5 = self.peer_md5
        item.queue = self.queue

        counts = self.count_blocks(function_match)

        imagebase = idaapi.get_imagebase()
        self_address = imagebase + function_match[self.self_name]
        item.setText(0, idaapi.get_short_name(self_address))
        item.setText(1, '%.8x' % self_address)
        item.setText(2, function_match[self.peer_name+'_name'])
        item.setText(3, '%.8x' % function_match[self.peer_name])
        item.setText(4, '%d' % counts['matched_block_counts'])
        item.setText(5, '%d' % counts['self_unidentified_block_counts'])
        item.setText(6, '%d' % counts['peer_unidentified_block_counts'])

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(("Source", "Address", "Target", "Address", "Matched", "Removed", "Added"))
        self.tree.setColumnWidth(0, 100)
        self.tree.setSortingEnabled(True)
        self.tree.itemDoubleClicked.connect(self.tree_double_clicked_handler)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        self.parent.setLayout(layout)
        
        self.queue = Queue(maxsize=0)
        worker = Thread(target=sync_worker, args=(self.queue,))
        worker.setDaemon(True)
        worker.start()

    def Show(self, title):
        return idaapi.PluginForm.Show(self, title, options = idaapi.PluginForm.FORM_PERSIST)

if __name__ == "__main__":
    form = FunctionsMatchViewer()
    form.Show("Function Matches")
    form.AddTestItems()
