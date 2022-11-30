#!/usr/bin/env python3
#-*- coding:utf-8 -*-

from PyQt5.QtCore import QThread,pyqtSignal
from Data import saveQueue
import io
from scapy.all import *

class filterthread(QThread):
    filtered=pyqtSignal(PacketList)
    def __init__(self):
        super().__init__()

    def run(self):
        pkt_to_filter=saveQueue.get_packet_to_filter()
        self.packet_list=pkt_to_filter.get()
        self.filter=pkt_to_filter.get()
        pkt_to_filter.queue.clear()

        scapy_pktlist=PacketList(res=self.packet_list)
        buf=io.BytesIO()
        wrpcap(buf,self.scapy_pktlist)

        filteredPkts=sniff(filter=self.filter,offline=buf)
        self.filtered.emit(filteredPkts)






        
