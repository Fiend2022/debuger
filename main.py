# debugger_gui.py
import sys
import threading
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTextEdit, QLineEdit, QLabel
)
from PyQt5.QtCore import QTimer, pyqtSignal
from AnnaDbg import AnnaDBG


class DebuggerWindow(QMainWindow):
    log_signal = pyqtSignal(str)
    event_signal = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("AnnaDBG — Threaded Edition")
        self.resize(900, 600)

        try:
            self.dbg = AnnaDBG()
        except Exception as e:
            print(f"Init error: {e}")
            sys.exit(1)

        self.log_signal.connect(self.on_log)
        self.event_signal.connect(self.on_event)

        self.setup_ui()
        self.is_debugging = False

        # Таймер для опроса событий (в UI-потоке!)
        self.event_timer = QTimer()
        self.event_timer.timeout.connect(self.check_events)
        self.event_timer.start(10)  # каждые 10 мс

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Launch
        launch_layout = QHBoxLayout()
        self.launch_edit = QLineEdit(r"C:\Windows\System32\notepad.exe")
        launch_btn = QPushButton("Launch")
        launch_btn.clicked.connect(self.on_launch)
        launch_layout.addWidget(QLabel("Program:"))
        launch_layout.addWidget(self.launch_edit)
        launch_layout.addWidget(launch_btn)
        layout.addLayout(launch_layout)

        # Controls
        ctrl_layout = QHBoxLayout()
        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self.dbg.run)
        self.step_btn = QPushButton("Step")
        self.step_btn.clicked.connect(self.dbg.step)
        ctrl_layout.addWidget(self.run_btn)
        ctrl_layout.addWidget(self.step_btn)
        layout.addLayout(ctrl_layout)

        # Log
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)

    def on_launch(self):
        path = self.launch_edit.text().strip()
        if not path:
            return

        def debug_task():
            try:
                self.log_signal.emit(f"[Thread] Launching: {path}")
                success = self.dbg.launchProcess(path)
                if success:
                    self.log_signal.emit("[Thread] Launch OK. Starting debug loop.")
                    self.is_debugging = True
                    # Основной цикл отладки — в этом потоке!
                    while self.is_debugging:
                        self.dbg.stepDebugLoop()  # ← неблокирующий шаг
                        # Небольшая пауза, чтобы не грузить CPU
                        threading.Event().wait(0.001)
                    self.log_signal.emit("[Thread] Debug loop stopped.")
                else:
                    self.log_signal.emit("[Thread] Launch FAILED!")
            except Exception as e:
                self.log_signal.emit(f"[Thread] Exception: {e}")

        # Запускаем отладку в ОТДЕЛЬНОМ потоке
        self.debug_thread = threading.Thread(target=debug_task, daemon=True)
        self.debug_thread.start()

    def check_events(self):
        # Безопасно опрашиваем события из UI-потока
        event = self.dbg.try_pop_event()
        if event:
            self.event_signal.emit(event)

    def on_event(self, event):
        msg = event.message.decode() if event.message else ""
        self.log_signal.emit(f"[Event {event.type}] {msg}")
        if event.type == 5:  # ProcessExit
            self.is_debugging = False

    def on_log(self, msg):
        self.log_view.append(msg)

    def closeEvent(self, event):
        self.is_debugging = False
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = DebuggerWindow()
    win.show()
    sys.exit(app.exec_())
    
