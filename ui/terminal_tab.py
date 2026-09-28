# ui/terminal_tab.py
import sys
import os
import subprocess
import shlex
import ipaddress
import qtawesome as qta
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QFrame, QFileDialog, QDialog
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal as pyqtSignal
from PySide6.QtGui import QFont, QTextCursor, QKeyEvent, QColor, QTextCharFormat

class CommandRunnerThread(QThread):
    output_signal = pyqtSignal(str)
    
    def __init__(self, cmd, cwd):
        super().__init__()
        self.cmd = cmd
        self.cwd = cwd
    
    def run(self):
        try:
            command = shlex.split(self.cmd, posix=(sys.platform != "win32"))
            result = subprocess.run(
                command, shell=False, cwd=self.cwd,
                capture_output=True, text=True,
                timeout=60, encoding="utf-8", errors="replace"
            )
            out = (result.stdout or "") + (result.stderr or "")
            self.output_signal.emit(out.rstrip())
        except subprocess.TimeoutExpired:
            self.output_signal.emit("[ERROR] Command execution timed out (60s)")
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {e}")

class TerminalTab(QWidget):
    """
    Enterprise TTY-Style Interactive Terminal for Network Security Monitor.
    Refactored matching CLITerminal & CLIWidget architecture.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.cwd = os.path.expanduser("~")
        self.command_history = []
        self.history_index = -1
        self.prompt = "$> "
        self.locked_length = 0
        self.runner = None
        
        self.init_ui()
        self.apply_theme()
        self.write_welcome()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(0)

        # 1. Top Toolbar Frame
        self.toolbar = QFrame()
        self.toolbar.setFixedHeight(45)
        self.toolbar.setObjectName("CLIToolbar")
        tool_lay = QHBoxLayout(self.toolbar)
        tool_lay.setContentsMargins(12, 0, 12, 0)
        tool_lay.setSpacing(10)

        self.btn_clear = self.create_tool_btn(" Clear", 'fa5s.eraser', self.clear_screen)
        self.btn_copy  = self.create_tool_btn(" Copy", 'fa5s.copy', self.copy_output)
        self.btn_save  = self.create_tool_btn(" Save Log", 'fa5s.save', self.save_log)
        self.btn_popout = self.create_tool_btn(" Pop-out Window", 'fa5s.external-link-alt', self.popout_window)

        tool_lay.addWidget(self.btn_clear)
        tool_lay.addWidget(self.btn_copy)
        tool_lay.addWidget(self.btn_save)
        tool_lay.addWidget(self.btn_popout)
        tool_lay.addStretch()

        self.conn_lbl = QLabel("🟢 Online | Restricted Diagnostics")
        self.conn_lbl.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 11px;")
        tool_lay.addWidget(self.conn_lbl)

        layout.addWidget(self.toolbar)

        # 2. Unified TTY Buffer Output Area
        self.buffer = QTextEdit()
        self.buffer.setObjectName("TTYBuffer")
        font = QFont("Consolas", 11)
        if sys.platform == "darwin":
            font = QFont("Menlo", 11)
        self.buffer.setFont(font)
        self.buffer.setAcceptRichText(False)
        self.buffer.installEventFilter(self)
        layout.addWidget(self.buffer, stretch=1)

        # 3. Status Bar
        self.status_bar = QFrame()
        self.status_bar.setFixedHeight(28)
        self.status_bar.setObjectName("CLIStatusBar")
        stat_lay = QHBoxLayout(self.status_bar)
        stat_lay.setContentsMargins(12, 0, 12, 0)
        
        self.latency_lbl = QLabel("[🟢] Shell Engine Active | UTF-8")
        self.latency_lbl.setStyleSheet("color: #888888; font-size: 10px;")
        stat_lay.addWidget(self.latency_lbl)
        stat_lay.addStretch()
        
        layout.addWidget(self.status_bar)

    def create_tool_btn(self, text, icon_name, slot):
        btn = QPushButton(text)
        btn.setIcon(qta.icon(icon_name, color="#ffffff"))
        btn.clicked.connect(slot)
        return btn

    def apply_theme(self):
        self.setStyleSheet("""
            QWidget { background-color: #0a0a0a; }
            #CLIToolbar { background-color: #1a1a1a; border: 1px solid #333333; border-top-left-radius: 6px; border-top-right-radius: 6px; }
            #CLIToolbar QPushButton {
                background: #252525; border: 1px solid #444444;
                padding: 4px 12px; color: #ffffff; border-radius: 4px; font-size: 11px; font-weight: bold;
            }
            #CLIToolbar QPushButton:hover { background-color: #007acc; border-color: #007acc; }
            #TTYBuffer { background-color: #000000; border: 1px solid #333333; color: #00ff00; padding: 10px; }
            #CLIStatusBar { background-color: #1a1a1a; border: 1px solid #333333; border-bottom-left-radius: 6px; border-bottom-right-radius: 6px; }
        """)

    def write_welcome(self):
        self.append_text("Network Security Monitor TTY Shell v2.0.0\n", "#ffffff")
        self.append_text("Proactive Enterprise Security & Command Engine\n", "#00e5ff")
        self.append_text("Type 'help' for available system commands (ipconfig, ping, netstat, tracert, arp).\n", "#888888")
        self.append_text("-" * 65 + "\n", "#444444")
        self.insert_prompt()

    def insert_prompt(self):
        self.append_text(f"{self.cwd} {self.prompt}", "#00ff00")
        self.buffer.moveCursor(QTextCursor.End)
        self.locked_length = len(self.buffer.toPlainText())

    def append_text(self, text, color="#00ff00"):
        cursor = self.buffer.textCursor()
        cursor.movePosition(QTextCursor.End)

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)

        cursor.insertText(text)
        self.buffer.setTextCursor(cursor)
        self.buffer.ensureCursorVisible()

    def get_user_input(self):
        all_text = self.buffer.toPlainText()
        return all_text[self.locked_length:]

    def handle_return(self):
        cmd = self.get_user_input().strip()
        self.append_text("\n", "#ffffff")

        if cmd:
            self.command_history.append(cmd)
            self.history_index = -1

            cmd_lower = cmd.lower()
            if cmd_lower == "help":
                self.append_text("Available Commands:\n", "#00e5ff")
                self.append_text("  cd <path>               Change current working directory\n", "#cccccc")
                self.append_text("  cls / clear             Clear terminal screen buffer\n", "#cccccc")
                self.append_text("  ipconfig /all           View network interface parameters\n", "#cccccc")
                self.append_text("  ping <ip>               Test ICMP latency response\n", "#cccccc")
                self.append_text("  tracert <host>          Trace network hop routes\n", "#cccccc")
                self.append_text("  netstat -an             List active network connections\n", "#cccccc")
                self.append_text("  arp -a                  Inspect system ARP cache\n", "#cccccc")
                self.insert_prompt()
                return

            if cmd_lower in ("cls", "clear"):
                self.clear_screen()
                return

            if cmd_lower.startswith("cd "):
                path = cmd[3:].strip().strip('"')
                try:
                    new = os.path.abspath(os.path.join(self.cwd, path))
                    if os.path.isdir(new):
                        self.cwd = new
                    else:
                        self.append_text(f"[ERROR] Directory not found: {path}\n", "#ff1744")
                except Exception as e:
                    self.append_text(f"[ERROR] {e}\n", "#ff1744")
                self.insert_prompt()
                return

            if not self._is_allowed_command(cmd):
                self.append_text("[ERROR] Command blocked. Only approved network diagnostics are allowed.\n", "#ff1744")
                self.insert_prompt()
                return

            # Execute via background CommandRunnerThread
            self.runner = CommandRunnerThread(cmd, self.cwd)
            self.runner.output_signal.connect(self._on_cmd_finished)
            self.runner.start()
            return

        self.insert_prompt()

    @staticmethod
    def _is_allowed_command(cmd):
        """Allow diagnostics only; reject shell metacharacters and command chaining."""
        if any(token in cmd for token in ("&&", "||", ";", "|", ">", "<", "`", "$", "\\")):
            return False
        try:
            tokens = shlex.split(cmd, posix=(sys.platform != "win32"))
        except ValueError:
            return False
        if not tokens:
            return False
        program = os.path.basename(tokens[0]).lower()
        args = tokens[1:]
        if program in {"arp", "netstat", "ifconfig", "hostname"}:
            return args in (["-a"], ["-an"], [], ["/all"])
        if program == "ip":
            return args in (["addr"], ["route"], ["-br", "addr"])
        if program == "ipconfig":
            return args in ([], ["/all"])
        if program in {"tracert", "traceroute"}:
            return len(args) == 1 and TerminalTab._valid_host(args[0])
        if program == "ping":
            if not args:
                return False
            host = args[-1]
            if not TerminalTab._valid_host(host):
                return False
            options = args[:-1]
            allowed_options = {"-c", "-W", "-w"}
            if any(opt not in allowed_options for opt in options[::2]):
                return False
            if len(options) % 2:
                return False
            for key, value in zip(options[::2], options[1::2]):
                if not value.isdigit() or int(value) < 1 or int(value) > 4:
                    return False
            return True
        return False

    @staticmethod
    def _valid_host(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return bool(value) and len(value) <= 253 and all(
                part and len(part) <= 63 for part in value.split(".")
            )

    def _on_cmd_finished(self, out):
        if out:
            color = "#ff1744" if "[ERROR]" in out else "#00ff88"
            self.append_text(out + "\n", color)
        self.insert_prompt()

    def eventFilter(self, source, event):
        if source == self.buffer and event.type() == event.Type.KeyPress:
            cursor = self.buffer.textCursor()
            pos = cursor.position()

            if pos < self.locked_length:
                if event.key() not in [Qt.Key_Left, Qt.Key_Right, Qt.Key_Up, Qt.Key_Down, Qt.Key_Control, Qt.Key_C]:
                    cursor.movePosition(QTextCursor.End)
                    self.buffer.setTextCursor(cursor)

            if event.key() == Qt.Key_Return:
                self.handle_return()
                return True

            elif event.key() == Qt.Key_Backspace:
                if pos <= self.locked_length:
                    return True

            elif event.key() == Qt.Key_Up:
                self.navigate_history(1)
                return True

            elif event.key() == Qt.Key_Down:
                self.navigate_history(-1)
                return True

        return super().eventFilter(source, event)

    def navigate_history(self, direction):
        if not self.command_history:
            return

        if self.history_index == -1:
            self.history_index = len(self.command_history) - 1
        else:
            self.history_index -= direction

        if self.history_index < 0:
            self.history_index = 0
        if self.history_index >= len(self.command_history):
            self.history_index = -1
            self.set_user_input("")
            return

        self.set_user_input(self.command_history[self.history_index])

    def set_user_input(self, text):
        cursor = self.buffer.textCursor()
        cursor.setPosition(self.locked_length)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        cursor.removeSelectedText()

        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#ffffff"))
        cursor.setCharFormat(fmt)
        cursor.insertText(text)
        self.buffer.setTextCursor(cursor)

    def clear_screen(self):
        self.buffer.clear()
        self.write_welcome()

    def copy_output(self):
        self.buffer.copy()

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save TTY Shell Log", "terminal_log.txt", "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.buffer.toPlainText())

    def popout_window(self):
        dialog = QDialog(None)
        dialog.setWindowFlags(Qt.Window | Qt.WindowMinMaxButtonsHint | Qt.WindowCloseButtonHint)
        dialog.setWindowTitle("Cyber Shield TTY Terminal - Pop-out Window")
        dialog.resize(900, 600)
        
        pop_tab = TerminalTab(dialog)
        pop_tab.btn_popout.setVisible(False) # Hide popout button in popped-out window
        
        lay = QVBoxLayout(dialog)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(pop_tab)
        
        dialog.exec()
