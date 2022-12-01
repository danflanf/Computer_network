from PyQt5.QtCore import *
from scapy.all import *
import io

from Data import saveQueue

class filterthread(QThread):
    filtered = pyqtSignal(PacketList)

    def __init__(self):
        super().__init__()

    def run(self):
        pkt_to_filter = saveQueue.get_packet_to_filter()
        self.packet_list = pkt_to_filter.get()
        self.filter = pkt_to_filter.get()
        pkt_to_filter.queue.clear()

        buf = io.BytesIO()
        wrpcap(buf, self.scapy_pktlist)

        filteredPkts = sniff(filter=self.filter, offline=buf)
        self.filtered.emit(filteredPkts)