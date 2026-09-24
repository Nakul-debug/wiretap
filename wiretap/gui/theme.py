"""Shared visual language for the WireTap desktop interface."""

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication


APP_STYLESHEET = """
QMainWindow, QWidget#appRoot { background: #0b1120; color: #e5edf8; }
QFrame#header, QFrame#controlBar, QFrame#panel, QFrame#metricCard, QFrame#emptyState {
    background: #111a2c; border: 1px solid #22304a; border-radius: 10px;
}
QFrame#header { border-radius: 0; border-left: 0; border-right: 0; border-top: 0; }
QFrame#controlBar { background: #0f1829; }
QFrame#metricCard { background: #111d31; }
QLabel#brand { font-size: 20px; font-weight: 700; color: #f4f8ff; }
QLabel#logoMark { background: #1674d1; color: white; border-radius: 8px; font-size: 13px; font-weight: 800; padding: 7px; }
QLabel#subtitle, QLabel#muted, QLabel#emptyDescription { color: #8ea0ba; }
QLabel#metricValue { color: #f4f8ff; font-size: 22px; font-weight: 700; }
QLabel#metricLabel { color: #8ea0ba; font-size: 10px; font-weight: 700; }
QLabel#sectionTitle { color: #f4f8ff; font-size: 13px; font-weight: 700; }
QLabel#emptyTitle { color: #dce8fa; font-size: 15px; font-weight: 700; }
QLabel#statusDot { color: #64748b; font-size: 17px; }
QLabel#statusDot[capturing="true"] { color: #34d399; }
QLabel#statusText { color: #aab9ce; font-weight: 600; }

QPushButton { background: #17243a; border: 1px solid #2a3a56; border-radius: 7px; color: #dce8fa; padding: 8px 13px; font-weight: 600; }
QPushButton:hover { background: #213451; border-color: #3b82f6; }
QPushButton:pressed { background: #132238; }
QPushButton:disabled { background: #111827; color: #63738c; border-color: #202d43; }
QPushButton#primaryButton { background: #1674d1; border-color: #2588e8; color: white; }
QPushButton#primaryButton:hover { background: #2588e8; }
QPushButton#dangerButton { color: #fecaca; }

QLineEdit, QComboBox { background: #0b1424; border: 1px solid #2a3a56; border-radius: 7px; color: #e5edf8; padding: 8px 10px; min-height: 18px; }
QLineEdit:focus, QComboBox:focus { border-color: #38bdf8; }
QLineEdit:disabled, QComboBox:disabled { color: #71809a; background: #0e1726; }
QComboBox QAbstractItemView { background: #111d31; border: 1px solid #2a3a56; color: #e5edf8; selection-background-color: #1d4f7e; }

QTabWidget::pane { border: 0; background: transparent; }
QTabBar::tab { background: transparent; color: #91a1ba; padding: 10px 16px; margin-right: 4px; border-bottom: 2px solid transparent; font-weight: 600; }
QTabBar::tab:selected { color: #eaf4ff; border-color: #38bdf8; }
QTabBar::tab:hover { color: #eaf4ff; background: #111d31; border-radius: 6px; }

QTableView { background: #0d1626; alternate-background-color: #101b2e; color: #dce8fa; border: 0; gridline-color: #1e2c44; selection-background-color: #164e78; selection-color: #ffffff; outline: 0; }
QTableView::item { padding: 7px 8px; border-bottom: 1px solid #17243a; }
QTableView::item:hover { background: #14233a; }
QTableView::item:selected { background: #164e78; }
QHeaderView::section { background: #111d31; color: #9db0c9; padding: 9px 8px; border: 0; border-bottom: 1px solid #2a3a56; font-size: 10px; font-weight: 700; }

QTreeWidget { background: #0d1626; border: 0; color: #dce8fa; alternate-background-color: #101b2e; }
QTreeWidget::item { padding: 5px; }
QTreeWidget::item:hover { background: #14233a; }
QTreeWidget::item:selected { background: #164e78; }
QTreeWidget::branch { background: #0d1626; }

QProgressBar { background: #0b1424; border: 0; border-radius: 4px; min-height: 8px; max-height: 8px; }
QProgressBar::chunk { background: #38bdf8; border-radius: 4px; }
QScrollBar:vertical { background: #0b1120; width: 10px; margin: 0; }
QScrollBar::handle:vertical { background: #33445f; min-height: 28px; border-radius: 5px; }
QScrollBar::handle:vertical:hover { background: #4b6388; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #0b1120; height: 10px; }
QScrollBar::handle:horizontal { background: #33445f; min-width: 28px; border-radius: 5px; }
QSplitter::handle { background: #22304a; }
QStatusBar { background: #0d1626; color: #8ea0ba; border-top: 1px solid #22304a; }
QMessageBox { background: #111a2c; color: #e5edf8; }
"""


def apply_theme() -> None:
    """Install Fusion and the common dark palette/QSS once per application."""
    app = QApplication.instance()
    if app is None:
        return
    app.setStyle("Fusion")
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#0b1120"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#e5edf8"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#0d1626"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#101b2e"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#e5edf8"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#17243a"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e5edf8"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#164e78"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(palette)
    app.setStyleSheet(APP_STYLESHEET)
