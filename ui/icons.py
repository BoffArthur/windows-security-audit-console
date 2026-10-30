"""Ícones coerentes usando a fonte de símbolos nativa do Windows."""

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap

ICON_FONT = "Segoe MDL2 Assets"
GLYPHS = {
    "home": "\uE80F", "alerts": "\uE7BA", "events": "\uE8FD",
    "status": "\uE9D9", "history": "\uE81C", "settings": "\uE713",
    "shield": "\uEA18", "clock": "\uE916",
    "clear": "\uE894", "delete": "\uE74D", "collect": "\uE896", "search": "\uE721",
}


def icon(name: str, color: str = "#38BDF8", size: int = 18) -> QIcon:
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.TextAntialiasing)
    painter.setFont(QFont(ICON_FONT, size))
    painter.setPen(QColor(color))
    painter.drawText(QRect(0, 0, size * 2, size * 2), Qt.AlignCenter, GLYPHS.get(name, "\uE10F"))
    painter.end()
    return QIcon(pixmap)


def status_icon(component: str) -> str:
    name = component.casefold()
    if "assinatura" in name or "atualiza" in name:
        return "clock"
    return "shield"
