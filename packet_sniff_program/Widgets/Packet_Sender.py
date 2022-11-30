#!/usr/bin/env python3
#-*- coding:utf-8 -*-

from PyQt5.QtWidgets import (QWidget, QSplitter, QGridLayout, QLabel,
                             QComboBox, QSpinBox, QDoubleSpinBox, QTextEdit,
                             QPushButton, QBoxLayout, QHBoxLayout, QCheckBox,
                             QTreeWidget, QTreeWidgetItem)
from PyQt5.QtCore import Qt

from scapy.all import *
import sys, re, collections
from Threads.Sender_Thread import senderthread
from Tools import scapy2ordereddict


class sender(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        MainLayout = QHBoxLayout(self)
        self.ContentTree = QTreeWidget(self)
        RightLayout = QGridLayout()
        MainLayout.addWidget(self.ContentTree)
        MainLayout.addLayout(RightLayout)

        Templates_Label = QLabel('Templates')
        self.Templates_ComboBox = QComboBox()
        Templates = ['TCP', 'UDP', 'ICMP', 'DNS']
        self.Templates_ComboBox.addItems(Templates)

        NumToSend_Label = QLabel('Num to send')
        self.NumToSend_SpinBox = QSpinBox()
        self.NumToSend_SpinBox.setValue(1)

        Interval_Label = QLabel('Interval')
        self.Interval_SpinBox = QDoubleSpinBox()
        self.Interval_SpinBox.setValue(0.0)

        Thread_Label = QLabel('Threads')
        self.Thread_SpinBox = QSpinBox()
        self.Thread_SpinBox.setValue(1)

        self.Follow_CheckBox = QCheckBox('Follow Stream')

        Send_Button = QPushButton('Send')
        Reset_Button = QPushButton('Reset')

        self.ContentTree.setColumnCount(2)
        self.ContentTree.setHeaderLabels(['Item', 'Detail'])

        RightLayout.addWidget(Templates_Label, 0, 0)
        RightLayout.addWidget(self.Templates_ComboBox, 0, 1)
        RightLayout.addWidget(NumToSend_Label, 1, 0)
        RightLayout.addWidget(self.NumToSend_SpinBox, 1, 1)
        RightLayout.addWidget(Interval_Label, 2, 0)
        RightLayout.addWidget(self.Interval_SpinBox, 2, 1)
        RightLayout.addWidget(Thread_Label, 3, 0)
        RightLayout.addWidget(self.Thread_SpinBox, 3, 1)
        RightLayout.addWidget(self.Follow_CheckBox, 4, 0)
        RightLayout.addWidget(Send_Button, 5, 0)
        RightLayout.addWidget(Reset_Button, 5, 1)
        RightLayout.setSpacing(15)
        RightLayout.setContentsMargins(10, 10, 10, 10)

        Send_Button.clicked.connect(self.SendPacket)
        Reset_Button.clicked.connect(self.reset_pkt)

        self.Templates_ComboBox.currentIndexChanged[int].connect(
            self.initTemplate)
        self.ContentTree.itemDoubleClicked[QTreeWidgetItem, int].connect(
            self.on_treeWidgetItem_doubleClicked)
        self.ContentTree.itemClicked[QTreeWidgetItem, int].connect(
            self.on_treeWidgetItem_itemClicked)
        self.initTemplate(0)

    def initPkt(self):
        self.ether_dic = {
            # 'dst': 'ff:ff:ff:ff:ff:ff',
            # 'src': '00:00:00:00:00:00',
            # 'type': 0x800
        }

        self.ip_dic = {
            # 'version': 4,
            # 'ihl': None,
            # 'tos': 0x0,
            # 'len': 0,
            # 'id': 0,
            # 'flags': 0,
            # 'ttl': 64,
            # 'proto': 'tcp',
            # 'chksum': None,
            # 'src': '127.0.0.1',
            # 'dst': '127.0.0.1'
        }
        self.tcp_dic = {
            # 'sport': 20,
            # 'dport': 80,
            # 'seq': 0,
            # 'ack': 0,
            # 'dataofs': None,
            # 'reserved': 0,
            # 'flags': 2,
            # 'window': 8192,
            # 'chksum': None,
            # 'urgptr': 0,
            # 'options': []
        }
        self.udp_dic = {}
        self.icmp_dic = {}
        self.dns_dic = {}
        self.data = b'payload'

    def SendPacket(self):
        if self.Templates_ComboBox.currentIndex() == 0:
            pkt = Ether(**self.ether_dic) / IP(**self.ip_dic) / TCP(
                **self.tcp_dic) / self.data
        elif self.Templates_ComboBox.currentIndex() == 1:
            pkt = Ether(**self.ether_dic) / IP(**self.ip_dic) / UDP(
                **self.udp_dic) / self.data
        elif self.Templates_ComboBox.currentIndex() == 2:
            pkt = Ether(**self.ether_dic) / IP(**self.ip_dic) / ICMP(
                **self.icmp_dic) / self.data
        elif self.Templates_ComboBox.currentIndex() == 3:
            pkt = Ether(**self.ether_dic) / IP(**self.ip_dic) / UDP(
                **self.udp_dic) / DNS(**self.dns_dic)

        baseNum = self.NumToSend_SpinBox.value() // self.Thread_SpinBox.value()
        remainderNum = self.NumToSend_SpinBox.value(
        ) % self.Thread_SpinBox.value()
        sendNum_list = [baseNum] * self.Thread_SpinBox.value()
        while remainderNum > 0:
            sendNum_list[remainderNum] += 1
            remainderNum -= 1
        tmp_thread = self.Thread_SpinBox.value()
        self.threadList=[]  #avoid being garbage collected by Python.
        while tmp_thread > 0:
            thread = senderthread()
            self.threadList.append(thread)
            thread.set_send_num(sendNum_list[tmp_thread - 1])
            thread.set_interval(self.Interval_SpinBox.value())
            thread.set_pkt(pkt)
            thread.start()
            tmp_thread -= 1
        
        self.initPkt()
    
    def reset_pkt(self):
        self.initTemplate(self.Templates_ComboBox.currentIndex())

    def initTemplate(self, index):
        self.initPkt()
        if index == 0:
            pkt = Ether() / IP() / TCP() / b'payload'
        elif index == 1:
            pkt = Ether() / IP() / UDP() / b'payload'
        elif index == 2:
            pkt = Ether() / IP() / ICMP() / b'payload'
        elif index == 3:
            pkt = Ether() / IP() / UDP() / DNS()
    
        self.packetDict=scapy2ordereddict.to_dict(pkt)
        self.buildTree()


    def buildTree(self):
        self.ContentTree.clear()
        self.doubleclicked = False
        self.lastColumn = 0
        for title in self.packetDict.keys():
            tree_item = QTreeWidgetItem(self.ContentTree)
            tree_item.setText(0, title)
            tree_item.setExpanded(True)
            detail_dic = self.packetDict[title]
            for i in detail_dic.keys():
               
                leaf = QTreeWidgetItem(tree_item, [i, str(detail_dic[i])])
                tree_item.addChild(leaf)
                leaf.setToolTip(1,str(detail_dic[i]))
                self.lastItem = tree_item
            self.ContentTree.addTopLevelItem(tree_item)

    def on_treeWidgetItem_doubleClicked(self, item, column):
        if column == 1:
            self.ContentTree.openPersistentEditor(item, column)
            self.pretext = item.text(1)
            self.doubleclicked = True
        self.lastColumn = column
        self.lastItem = item

    def on_treeWidgetItem_itemClicked(self, item, column):
        if self.lastColumn != column or self.lastItem != item:
            if self.doubleclicked:
                self.ContentTree.closePersistentEditor(self.lastItem,
                                                       self.lastColumn)
                self.doubleclicked = False
                if self.pretext != self.lastItem.text(1):
                    parent_title = self.lastItem.parent().text(0)
                    if parent_title == 'Ethernet':
                        self.ether_dic[self.lastItem.text(
                            0)] = self.lastItem.text(1)
                    elif parent_title == 'IP':
                        self.ip_dic[self.lastItem.text(
                            0)] = self.lastItem.text(1)
                    elif parent_title == 'UDP':
                        self.udp_dic[self.lastItem.text(
                            0)] = self.lastItem.text(1)
                    elif parent_title == 'TCP':
                        self.tcp_dic[self.lastItem.text(
                            0)] = self.lastItem.text(1)
                    elif parent_title == 'ICMP':
                        self.icmp_dic[self.lastItem.text(
                            0)] = self.lastItem.text(1)
                    elif parent_title == 'DNS':
                        self.dns_dic[self.lastItem.text(
                            0)] = self.lastItem.text(1)
                    elif parent_title == 'Raw':
                        self.data = self.lastItem.text(1)

        self.lastColumn = column
        self.lastItem = item


class FakeOut:
    def __init__(self):
        self.str = ''

    def write(self, s):
        self.str += s

    def show(self):
        print(self.str)