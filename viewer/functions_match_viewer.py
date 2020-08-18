import idaapi
import idc
from PyQt5 import QtGui, QtCore, QtWidgets

def tree_double_clicked_handler(item, column_no):
    source_address = item.source_address
    if idc.isEnabled(source_address):
        idaapi.jumpto(source_address)

class FunctionsMatchViewer(idaapi.PluginForm):
    def add_item(self, source_address, target_address, matched_block_counts, self_unidentified_block_counts, peer_unidentified_block_counts):
        item = QtWidgets.QTreeWidgetItem(self.tree)
        item.source_address = source_address
        item.target_address = target_address
        item.setText(0, '%.8x' % source_address)
        item.setText(1, '%.8x' % target_address)
        item.setText(2, '%.8d' % matched_block_counts)
        item.setText(3, '%.8d' % self_unidentified_block_counts)
        item.setText(4, '%.8d' % peer_unidentified_block_counts)

    def OnCreate(self, form):
        self.parent = idaapi.PluginForm.FormToPyQtWidget(form)

        self.tree = QtWidgets.QTreeWidget()
        self.tree.setHeaderLabels(("Source", "Target", "Matched", "Removed", "Added"))
        self.tree.setColumnWidth(0, 100)
        self.tree.setSortingEnabled(True)
        self.tree.itemDoubleClicked.connect(tree_double_clicked_handler)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree)
        self.parent.setLayout(layout)

    def Show(self, title):
        return idaapi.PluginForm.Show(self, title, options = idaapi.PluginForm.FORM_PERSIST)

if __name__ == "__main__":
    form = FunctionsMatchViewer()
    form.Show("Function Matches")
    form.AddTestItems()
