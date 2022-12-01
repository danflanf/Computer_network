from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

from Threads.Cap_Thread import capturethread
from Data import saveQueue
from Tools import scapy2ordereddict


class capture(QWidget):
    filterApplied = pyqtSignal()
    def __init__(self):
        super().__init__()
        self.initUI()
        self.packet_list = []

    def initUI(self):
        mainLayout = QVBoxLayout(self)

        filter_layout = QHBoxLayout()
        filter_label = QLabel('Filter')
        self.filter_lineEdit = QLineEdit()
        filter_apply_btn = QPushButton('Apply')
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_lineEdit)
        filter_layout.addWidget(filter_apply_btn)
        mainLayout.addLayout(filter_layout)
        self.filter = ''

        splitterMain = QSplitter(Qt.Vertical, self)
        self.QuickView = QTableWidget(splitterMain)
        self.QuickView.setColumnCount(6)
        self.QuickView.setHorizontalHeaderLabels(['번호', '시간', 'Source', 'Destination', 'Protocol', '크기'])
        self.QuickView.setColumnWidth(0, 60)
        self.QuickView.verticalHeader().setVisible(False)
        #데이터 길이에 따라 테이블 길이 변경
        self.QuickView.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.QuickView.setShowGrid(False)
        self.QuickView.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.QuickView.setSelectionMode(QTableWidget.ExtendedSelection)
        # 테이블 수정 불가능하게 설정
        self.QuickView.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # 테이블 정렬기능
        self.QuickView.setSortingEnabled(True)

        self.DetailView = QTreeWidget(splitterMain)
        self.DetailView.setColumnCount(2)
        self.DetailView.setHeaderLabels(['Item', 'Detail'])
        mainLayout.addWidget(splitterMain)

        bottomLayout = QHBoxLayout()
        self.start_btn = QPushButton('START')
        self.stop_btn = QPushButton('STOP')
        self.restart_btn = QPushButton('Restart')
        self.clear_btn = QPushButton('CLEAR')
        self.intercept_CheckBox = QCheckBox('Intercept Packets')
        bottomLayout.addWidget(self.start_btn)
        bottomLayout.addWidget(self.stop_btn)
        bottomLayout.addWidget(self.restart_btn)
        bottomLayout.addWidget(self.clear_btn)
        bottomLayout.addWidget(self.intercept_CheckBox)
        bottomLayout.addStretch()
        self.stop_btn.setEnabled(False)
        self.restart_btn.setEnabled(False)
        mainLayout.addLayout(bottomLayout)

        self.start_btn.clicked.connect(self.start_sniff)
   
        self.stop_btn.clicked.connect(self.stop_sniff)
        self.QuickView.currentItemChanged.connect(self.show_current_detail)
        self.restart_btn.clicked.connect(self.restart_sniff)
        self.clear_btn.clicked.connect(self.clear_widget)
        self.count = 0

    def start_sniff(self):
        self.cap_thread = capturethread()
        self.cap_thread.newPkt.connect(self.init_display)
        self.cap_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.restart_btn.setEnabled(False)

    def init_display(self, item_list,pkt):
        self.packet_list.append(pkt)
        self.QuickView.insertRow(self.QuickView.rowCount())

        for i in range(6):
            self.QuickView.setItem(self.QuickView.rowCount()-1, i, item_list[i])

    def buildTree(self):
        self.DetailView.clear()

        for title in self.packetDict.keys():
            tree_item = QTreeWidgetItem(self.DetailView)
            tree_item.setText(0, title)
            tree_item.setExpanded(True)
            detail_dic = self.packetDict[title]

            for i in detail_dic.keys():
                leaf = QTreeWidgetItem(tree_item, [i, str(detail_dic[i])])
                leaf.setToolTip(1,str(detail_dic[i]))
                tree_item.addChild(leaf)

            self.DetailView.addTopLevelItem(tree_item)

    def stop_sniff(self):
        self.cap_thread.set_stopper(True)
        self.start_btn.setEnabled(True)
        self.restart_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def restart_sniff(self):
        self.pkt_queue = saveQueue.get_pkt()
        self.label_queue = saveQueue.get_label()
        with self.label_queue.mutex:
            self.label_queue.queue.clear()
        with self.pkt_queue.mutex:
            self.pkt_queue.queue.clear()

        self.packet_list.clear()
        self.QuickView.clearContents()
        self.DetailView.clear()
        self.start_sniff()

    def show_current_detail(self):
        if self.packet_list:
            pkt = self.packet_list[self.QuickView.currentRow()]
            self.packetDict = scapy2ordereddict.to_dict(pkt)
            self.buildTree()

    def clear_widget(self):
        self.pkt_queue = saveQueue.get_pkt()
        self.label_queue = saveQueue.get_label()
        with self.label_queue.mutex:
            self.label_queue.queue.clear()
        with self.pkt_queue.mutex:
            self.pkt_queue.queue.clear()

        self.packet_list.clear()
        self.QuickView.clearContents()
        self.DetailView.clear()

class FakeOut:
    def __init__(self):
        self.str = ''

    def write(self, s):
        self.str += s

    def show(self):
        print(self.str)