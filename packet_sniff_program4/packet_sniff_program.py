from PyQt5.QtWidgets import QApplication
import sys

from Widgets.MainWindow_Widget import MainWindow

if __name__ == '__main__':
    app = QApplication(sys.argv)
    main = MainWindow()
    main.show()
    exit(app.exec_())