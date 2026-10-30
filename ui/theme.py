"""Tema visual da interface do WSAC."""

STYLE = """
QWidget { background:#080F0E; color:#E5EDF7; font-family:"Cascadia Mono","Consolas",monospace; font-size:10pt; }
QMainWindow { background:#080F0E; }
QLabel { background:transparent; }
QFrame#toolbar,QFrame#footer,QFrame#signalBox { background:#101A19; border:1px solid #2D403D; }
QPushButton,QSpinBox,QComboBox,QLineEdit,QDateTimeEdit { background:#121E1C; color:#E5EDF7; border:1px solid #3A504B; padding:6px 9px; }
QPushButton:hover,QComboBox:hover,QLineEdit:hover,QDateTimeEdit:hover { background:#1A2B28; border-color:#38BDF8; }
QPushButton:disabled { color:#718096; border-color:#273733; }
QPushButton#primary { background:#12393D; border-color:#22D3C5; font-weight:700; }
QTabWidget::pane { border:1px solid #2D403D; background:#0C1514; }
QTabBar::tab { background:#101A19; color:#B8C7C3; border:1px solid #2D403D; padding:8px 14px; }
QTabBar::tab:selected { background:#192825; color:#F8FAFC; border-bottom:2px solid #38BDF8; }
QPlainTextEdit,QTableWidget,QListWidget { background:#0A1211; color:#E5EDF7; border:0; selection-background-color:#24423C; selection-color:#fff; }
QListWidget::item { padding:7px; border-bottom:1px solid #202F2C; }
QListWidget::item:selected { background:#1B322E; color:#ffffff; }
QTableWidget { gridline-color:#263835; alternate-background-color:#101A19; }
QTableWidget::item { padding:6px; border-bottom:1px solid #202F2C; }
QHeaderView::section { background:#172321; color:#E5EDF7; border:0; border-right:1px solid #2D403D; border-bottom:1px solid #3A504B; padding:7px; font-weight:700; }
QSplitter::handle { background:#2D403D; width:1px; }
QLabel#signal { font-weight:700; padding:4px 8px; }
QLabel#footerText { color:#B8C7DA; padding:2px; }
QLabel#footerAuthor { color:#94A3B8; padding:2px; font-style:italic; }
QGroupBox { border:1px solid #2D403D; margin-top:12px; padding:12px 8px 8px 8px; color:#C7D5D0; }
QGroupBox::title { subcontrol-origin:margin; left:8px; padding:0 5px; }
QProgressBar { background:#0A1211; border:1px solid #2D403D; height:8px; color:transparent; }
QProgressBar::chunk { background:#38BDF8; }
QScrollBar:vertical,QScrollBar:horizontal { background:#080F0E; border:0; }
QScrollBar::handle { background:#3A504B; min-height:24px; min-width:24px; }
"""


def apply_palette(app, QPalette, QColor) -> None:
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#080F0E"))
    palette.setColor(QPalette.WindowText, QColor("#E5EDF7"))
    palette.setColor(QPalette.Base, QColor("#0A1211"))
    palette.setColor(QPalette.Text, QColor("#E5EDF7"))
    palette.setColor(QPalette.Highlight, QColor("#24423C"))
    palette.setColor(QPalette.HighlightedText, QColor("#fff"))
    app.setPalette(palette)
