#!/usr/bin/env python3
#-*- coding:utf-8 -*-

from PyQt5.QtWidgets import QDockWidget, QMainWindow, QWidget, QAction, QMenu
from PyQt5.QtCore import Qt
from Widgets.Capture_Packet import capture
from Widgets.Packet_Sender import sender


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        sender_widget = sender()
        capture_widget = capture()
        DockWidget_Sender = QDockWidget('전송', self)
        DockWidget_Sender.setWidget(sender_widget)
        DockWidget_Capture = QDockWidget('캡쳐', self)
        DockWidget_Capture.setWidget(capture_widget)

        DockWidget_Sender.setFeatures(QDockWidget.NoDockWidgetFeatures)
        DockWidget_Sender.setAllowedAreas(Qt.TopDockWidgetArea)
        self.addDockWidget(Qt.TopDockWidgetArea, DockWidget_Sender)

        DockWidget_Capture.setFeatures(QDockWidget.DockWidgetFloatable |
                                       QDockWidget.DockWidgetMovable)
        DockWidget_Capture.setAllowedAreas(Qt.TopDockWidgetArea)
        self.addDockWidget(Qt.TopDockWidgetArea, DockWidget_Capture)

        self.tabifyDockWidget(DockWidget_Sender, DockWidget_Capture)
        DockWidget_Sender.raise_()

        statusbar = self.statusBar()
        menubar = self.menuBar()

        filemenu = menubar.addMenu('&File')
        import_act = QAction('Import', self)
        export_act = QAction('Export', self)
        exit_act = QAction('Exit', self)
        filemenu.addAction(import_act)
        filemenu.addAction(export_act)
        filemenu.addSeparator()
        filemenu.addAction(exit_act)

        aboutmenu = menubar.addMenu('&About')
        about_act = QAction('About', self)
        aboutmenu.addAction(about_act)

        self.setWindowTitle('패킷분석 프로그램')