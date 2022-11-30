#!/usr/bin/env python3
#-*- coding:utf-8 -*-

from PyQt5.QtCore import QThread
from scapy.all import *


class senderthread(QThread):
    def __init__(self):
        super().__init__()
        self.send_num = 1
        self.interval = 0.0
        self.pkt = None

    def run(self):
        self.send_pkt()

    def set_send_num(self, num):
        self.send_num = num

    def set_interval(self, num):
        self.interval = num

    def set_pkt(self, p):
        self.pkt = p

    def send_pkt(self):
        sendp(self.pkt, inter=self.interval, count=self.send_num)
