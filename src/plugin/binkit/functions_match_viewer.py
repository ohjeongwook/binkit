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
    def color_lines(self, start, end, color):
        address = idaapi.get_imagebase() + start
        while address < idaapi.get_imagebase() + end:
            idaapi.set_item_color(address, color)
            address += ida_bytes.get_item_size(address)

    def color_node(self, addresses, bg_color, frame_color = 0x000000):
        if len(addresses) <= 0:
            return

        func = idaapi.get_func(idaapi.get_imagebase() + addresses[0])
        flowchart_ = idaapi.FlowChart(func)

        address_map = {}
        for address in addresses:
            address_map[idaapi.get_imagebase() + address] = 1

        for code_block in flowchart_:
            if not code_block.start_ea in address_map:
                continue

            node_info = idaapi.node_info_t()
            node_info.bg_color = bg_color
            node_info.frame_color = frame_color
            idaapi.set_node_info(func.start_ea, code_block.id, node_info, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)

    def set_basic_blocks_color(self):
        for function_match in self.match_results['function_matches']:
            self.matched_block_color_function_match(function_match)

    def add_items(self, match_results, self_name, peer_name, peer_md5, matched_block_color, unidentified_block_color):
        self.matched_block_color = matched_block_color
        self.unidentified_block_color = unidentified_block_color
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
    
    def tree_double_clicked_handler(self, ix):
        item = self.items[ix.row()]
        idaapi.jumpto(idaapi.get_imagebase() + item.function_match[item.self_name])
        commands = {'md5': item.peer_md5, 'list': []}
        commands['list'].append(({'name': 'jumpto', 'address': item.function_match[item.peer_name]}))

        self_basic_block_addresses = []
        peer_basic_block_addresses = []
        if 'matches' in item.function_match:
            for match_data in item.function_match['matches']:
                self_basic_block_addresses.append(match_data[self.self_name])
                peer_basic_block_addresses.append(match_data[self.peer_name])
                self.color_lines(match_data[self.self_name], match_data[self.self_name+'_end'], self.matched_block_color)
                commands['list'].append({'name': 'color_lines', 'start': match_data[self.peer_name], 'end': match_data[self.peer_name+'_end'], 'color': self.matched_block_color})

        self.color_node(self_basic_block_addresses, self.matched_block_color)
        commands['list'].append({'name': 'color_node', 'addresses': peer_basic_block_addresses, 'bg_color': self.matched_block_color})
       
        if 'unidentified_blocks' in item.function_match:
            self_basic_block_addresses = []
            for basic_block in item.function_match['unidentified_blocks'][self.self_name+'s']:
                self_basic_block_addresses.append(basic_block['start'])
                self.color_lines(basic_block['start'], basic_block['end'], self.unidentified_block_color)
            self.color_node(self_basic_block_addresses, self.unidentified_block_color)

            peer_basic_block_addresses = []
            for basic_block in item.function_match['unidentified_blocks'][self.peer_name+'s']:
                peer_basic_block_addresses.append(basic_block['start'])
                commands['list'].append({'name': 'color_lines', 'start': basic_block['start'], 'end': basic_block['end'], 'color': self.unidentified_block_color})
            commands['list'].append({'name': 'color_node', 'addresses': peer_basic_block_addresses, 'bg_color': self.unidentified_block_color})

        item.queue.put(commands)

    def add_item(self, function_match):
        imagebase = idaapi.get_imagebase()
        self_address = imagebase + function_match[self.self_name]        
        counts = self.count_blocks(function_match)

        root = self.model.invisibleRootItem()
        root.appendRow([
            QtGui.QStandardItem(idaapi.get_short_name(self_address)),
            QtGui.QStandardItem('%.8x' % self_address),
            QtGui.QStandardItem(function_match[self.peer_name+'_name']),
            QtGui.QStandardItem('%.8x' % function_match[self.peer_name]),
            QtGui.QStandardItem('%d' % counts['matched_block_counts']),
            QtGui.QStandardItem('%d' % counts['self_unidentified_block_counts']),
            QtGui.QStandardItem('%d' % counts['peer_unidentified_block_counts'])
        ])

        class Item:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        self.items.append(Item(
                function_match = function_match,
                self_name = self.self_name,
                peer_name = self.peer_name,
                peer_md5 = self.peer_md5,
                queue = self.queue
        ))

    def search_input_changed(self, text):
        print(text)

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

        self.tree = QtWidgets.QTreeView()
        self.tree.setSortingEnabled(True)
        self.tree.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tree.doubleClicked.connect(self.tree_double_clicked_handler)

        self.items = []
        self.model = QtGui.QStandardItemModel(self.tree)
        self.model.setHorizontalHeaderLabels(("Source", "Address", "Target", "Address", "Matched", "Removed", "Added"))
        self.tree.setModel(self.model)

        self.search_input = QtWidgets.QLineEdit()
        self.search_input.textChanged.connect(self.search_input_changed)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        layout.addWidget(self.search_input)
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
