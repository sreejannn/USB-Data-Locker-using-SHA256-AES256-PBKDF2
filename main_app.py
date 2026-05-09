import sys
import os

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QLineEdit,
    QProgressBar, QFileDialog, QTextEdit, QCheckBox, QSpinBox, QHBoxLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from crypto_utils import encrypt_file, decrypt_file, secure_delete

class WorkerEncrypt(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, src, dest, password):
        super().__init__()
        self.src = src
        self.dest = dest
        self.password = password

    def run(self):
        try:
            encrypt_file(self.src, self.dest, self.password)
            self.progress.emit(100)
            self.finished.emit(True, "Encryption finished")
        except Exception as e:
            self.finished.emit(False, str(e))

class WorkerDecrypt(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, src, dest, password):
        super().__init__()
        self.src = src
        self.dest = dest
        self.password = password

    def run(self):
        try:
            decrypt_file(self.src, self.dest, self.password)
            self.progress.emit(100)
            self.finished.emit(True, "Decryption finished")
        except Exception as e:
            self.finished.emit(False, str(e))

class DragDropLabel(QLabel):
    filesDropped = pyqtSignal(list)
    def __init__(self):
        super().__init__('Drop files here or click "Browse"')
        self.setStyleSheet('border: 2px dashed #aaa; padding: 20px;')
        self.setAlignment(Qt.AlignCenter)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.accept()
        else:
            e.ignore()

    def dropEvent(self, e):
        files = [u.toLocalFile() for u in e.mimeData().urls()]
        self.filesDropped.emit(files)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CRYPT LOCK (prototype)")
        self.resize(600, 400)
        layout = QVBoxLayout()

        self.drop = DragDropLabel()
        self.drop.filesDropped.connect(self.handle_drop)
        layout.addWidget(self.drop)

        hb = QHBoxLayout()
        self.browseBtn = QPushButton("Browse")
        self.browseBtn.clicked.connect(self.browse_file)
        hb.addWidget(self.browseBtn)
        self.selectedPath = QLineEdit()
        hb.addWidget(self.selectedPath)
        layout.addLayout(hb)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Enter password")
        layout.addWidget(self.password)

        opts = QHBoxLayout()
        self.self_destruct_cb = QCheckBox("Enable self-destruct")
        opts.addWidget(self.self_destruct_cb)
        opts.addWidget(QLabel("Max failed attempts:"))
        self.max_attempts = QSpinBox()
        self.max_attempts.setMinimum(1)
        self.max_attempts.setMaximum(20)
        self.max_attempts.setValue(5)
        opts.addWidget(self.max_attempts)
        layout.addLayout(opts)

        btns = QHBoxLayout()
        self.encryptBtn = QPushButton("Encrypt")
        self.encryptBtn.clicked.connect(self.encrypt_clicked)
        btns.addWidget(self.encryptBtn)

        self.decryptBtn = QPushButton("Decrypt")
        self.decryptBtn.clicked.connect(self.decrypt_clicked)
        btns.addWidget(self.decryptBtn)
        layout.addLayout(btns)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        layout.addWidget(self.log)

        self.setLayout(layout)
        self.attempts_db = {}

    def handle_drop(self, files):
        if files:
            self.selectedPath.setText(files[0])

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select file")
        if path:
            self.selectedPath.setText(path)

    def log_msg(self, text):
        self.log.append(text)

    def encrypt_clicked(self):
        src = self.selectedPath.text().strip()
        if not src or not os.path.isfile(src):
            self.log_msg("No valid file selected")
            return
        pwd = self.password.text()
        if not pwd:
            self.log_msg("Enter a password")
            return
        dest = src + ".cl"
        self.worker = WorkerEncrypt(src, dest, pwd)
        self.worker.progress.connect(self.progress.setValue)
        self.worker.finished.connect(self.on_encrypt_finished)
        self.log_msg(f"Starting encryption: {src} -> {dest}")
        self.worker.start()

    def on_encrypt_finished(self, ok, msg):
        self.log_msg(msg)
        if ok:
            self.progress.setValue(100)

    def decrypt_clicked(self):
        src = self.selectedPath.text().strip()
        if not src or not os.path.isfile(src):
            self.log_msg("No valid file selected")
            return
        pwd = self.password.text()
        if not pwd:
            self.log_msg("Enter a password")
            return
        dest = src + ".dec"
        attempts = self.attempts_db.get(src, 0)
        max_a = self.max_attempts.value() if self.self_destruct_cb.isChecked() else None
        self.worker = WorkerDecrypt(src, dest, pwd)
        self.worker.progress.connect(self.progress.setValue)

        def finished(ok, msg):
            nonlocal attempts
            if ok:
                self.log_msg("Decryption successful")
                self.attempts_db[src] = 0
            else:
                self.log_msg(f"Decryption failed: {msg}")
                attempts += 1
                self.attempts_db[src] = attempts
                if max_a is not None and attempts >= max_a:
                    self.log_msg("Max attempts reached: self-destructing file")
                    try:
                        secure_delete(src)
                        self.log_msg("File securely deleted")
                    except Exception as e:
                        self.log_msg("Failed to securely delete: " + str(e))
            self.progress.setValue(0)
        self.worker.finished.connect(finished)
        self.log_msg(f"Starting decryption: {src} -> {dest}")
        self.worker.start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
