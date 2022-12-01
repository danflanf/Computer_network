from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

from Widgets.Capture_Packet import capture

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        capture_widget = capture()
        DockWidget_Capture = QDockWidget('캡쳐', self)
        DockWidget_Capture.setWidget(capture_widget)

        DockWidget_Capture.setFeatures(QDockWidget.DockWidgetFloatable | QDockWidget.DockWidgetMovable)
        DockWidget_Capture.setAllowedAreas(Qt.TopDockWidgetArea)
        self.addDockWidget(Qt.TopDockWidgetArea, DockWidget_Capture)

        self.setWindowTitle('패킷분석 프로그램')