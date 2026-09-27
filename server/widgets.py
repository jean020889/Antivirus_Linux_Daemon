# server/widgets.py
"""Widgets reutilizables para el dashboard PyQt6."""
from PyQt6.QtWidgets import (QFrame, QLabel, QVBoxLayout, QHBoxLayout,
                             QSizePolicy, QPushButton, QTableWidget,
                             QTableWidgetItem, QHeaderView, QAbstractItemView)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor


class Card(QFrame):
    """Tarjeta de KPI."""
    def __init__(self, label, value="0", color="blue", parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setMinimumHeight(110)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        self.label_widget = QLabel(label.upper())
        self.label_widget.setObjectName("CardLabel")

        self.value_widget = QLabel(str(value))
        self.value_widget.setObjectName(f"CardValue{color.capitalize()}")

        layout.addWidget(self.label_widget)
        layout.addWidget(self.value_widget)
        layout.addStretch()

    def set_value(self, value):
        self.value_widget.setText(str(value))


class StatusBadge(QLabel):
    """Badge de estado con color según severidad."""
    COLORS = {
        "critical": "#f85149",
        "high": "#d29922",
        "medium": "#1f6feb",
        "low": "#6e7681",
        "info": "#30363d",
        "open": "#f85149",
        "acknowledged": "#d29922",
        "resolved": "#3fb950",
        "active": "#3fb950",
        "inactive": "#6e7681",
    }

    def __init__(self, text, kind="info", parent=None):
        super().__init__(text.upper(), parent)
        color = self.COLORS.get(kind, "#30363d")
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {color};
                color: white;
                padding: 2px 10px;
                border-radius: 10px;
                font-weight: bold;
                font-size: 11px;
            }}
        """)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMaximumWidth(100)


class DataTable(QTableWidget):
    """Tabla de datos profesional."""
    row_double_clicked = pyqtSignal(int)

    def __init__(self, headers, parent=None):
        super().__init__(parent)
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.setShowGrid(False)
        self.setSortingEnabled(True)

        self.itemDoubleClicked.connect(
            lambda item: self.row_double_clicked.emit(item.row())
        )

    def add_row(self, values, colors=None, severity_col=None):
        """Añade una fila a la tabla."""
        row = self.rowCount()
        self.insertRow(row)

        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value) if value is not None else "")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)

            if colors and col in colors:
                item.setForeground(QColor(colors[col]))

            self.setItem(row, col, item)

        return row

    def clear_rows(self):
        self.setRowCount(0)


class NavButton(QPushButton):
    """Botón de navegación del sidebar."""
    def __init__(self, icon, text, parent=None):
        super().__init__(f"  {icon}   {text}", parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
