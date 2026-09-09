import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

ApplicationWindow {
    visible: true
    width: 900
    height: 650
    title: "🛡️ Antivirus Profesional Linux"
    color: "#1e1e1e"

    // Colores
    property color bgColor: "#2d2d2d"
    property color cardColor: "#3c3c3c"
    property color accentColor: "#4a9eff"
    property color textColor: "#e0e0e0"
    property color dangerColor: "#ff5555"
    property color successColor: "#50fa7b"
    property color warningColor: "#f1fa8c"

    // Conexión con el backend
    Connections {
        target: backend
        onLog_signal: function(message, color) {
            logArea.append("<font color='" + color + "'>" + message + "</font>")
        }
        onStatus_signal: function(status, color) {
            statusLabel.text = status
            statusLabel.color = color
        }
        onScan_finished: function(files, threats) {
            filesLabel.text = files
            threatsLabel.text = threats
        }
    }

    // Componente reutilizable: tarjeta
    Component {
        id: card
        Rectangle {
            color: cardColor
            radius: 8
            border.color: "#555"
            border.width: 1
            Layout.fillWidth: true
            Layout.margins: 5
        }
    }

    // Panel izquierdo (estado)
    ColumnLayout {
        id: leftPanel
        anchors.left: parent.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.margins: 10
        width: 220
        spacing: 10

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 120
            color: cardColor
            radius: 8
            border.color: "#555"

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 10
                spacing: 4
                Text {
                    text: "🛡️ PROTECCIÓN"
                    color: accentColor
                    font.bold: true
                    font.pixelSize: 14
                }
                Text {
                    id: statusLabel
                    text: "Inactivo"
                    color: "gray"
                    font.pixelSize: 16
                }
                RowLayout {
                    Text { text: "Última actualización:"; color: textColor; font.pixelSize: 11 }
                    Text {
                        text: backend.get_last_update()
                        color: textColor
                        font.pixelSize: 11
                    }
                }
                RowLayout {
                    Text { text: "Cuarentena:"; color: textColor; font.pixelSize: 11 }
                    Text {
                        text: backend.get_quarantine_count()
                        color: textColor
                        font.pixelSize: 11
                    }
                }
                RowLayout {
                    Text { text: "Archivos analizados:"; color: textColor; font.pixelSize: 11 }
                    Text {
                        id: filesLabel
                        text: "0"
                        color: textColor
                        font.pixelSize: 11
                    }
                }
                RowLayout {
                    Text { text: "Amenazas:"; color: textColor; font.pixelSize: 11 }
                    Text {
                        id: threatsLabel
                        text: "0"
                        color: dangerColor
                        font.pixelSize: 11
                        font.bold: true
                    }
                }
            }
        }

        // Botones de acción rápida
        Button {
            text: "📂 Escaneo Rápido (Descargas)"
            Layout.fillWidth: true
            onClicked: backend.quick_scan()
            background: Rectangle {
                color: parent.hovered ? "#4a6a9f" : accentColor
                radius: 5
            }
            contentItem: Text { text: parent.text; color: "white"; font.bold: true }
        }

        Button {
            text: "💻 Escaneo Completo (Sistema)"
            Layout.fillWidth: true
            onClicked: backend.full_scan()
            background: Rectangle {
                color: parent.hovered ? "#cc4444" : dangerColor
                radius: 5
            }
            contentItem: Text { text: parent.text; color: "white"; font.bold: true }
        }

        Button {
            text: "🧠 Escanear Procesos"
            Layout.fillWidth: true
            onClicked: backend.scan_memory()
            background: Rectangle {
                color: parent.hovered ? "#6a4a9f" : "#9b59b6"
                radius: 5
            }
            contentItem: Text { text: parent.text; color: "white"; font.bold: true }
        }

        Button {
            text: "🔄 Actualizar Firmas"
            Layout.fillWidth: true
            onClicked: backend.update_signatures()
            background: Rectangle {
                color: parent.hovered ? "#4a6a4a" : "#2ecc71"
                radius: 5
            }
            contentItem: Text { text: parent.text; color: "white"; font.bold: true }
        }
    }

    // Panel derecho: tareas programadas y logs
    ColumnLayout {
        anchors.left: leftPanel.right
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.margins: 10
        spacing: 10

        // Tareas programadas
        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 160
            color: cardColor
            radius: 8
            border.color: "#555"

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 10
                spacing: 6
                Text {
                    text: "📋 Tareas Programadas"
                    color: accentColor
                    font.bold: true
                    font.pixelSize: 14
                }
                ListView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    model: backend.get_scheduled_tasks()
                    delegate: Rectangle {
                        width: parent.width
                        height: 28
                        color: index % 2 ? "#2a2a2a" : "transparent"
                        RowLayout {
                            anchors.fill: parent
                            anchors.margins: 5
                            Text {
                                text: modelData.name
                                color: textColor
                                font.pixelSize: 11
                                Layout.preferredWidth: parent.width * 0.5
                            }
                            Text {
                                text: modelData.hour
                                color: textColor
                                font.pixelSize: 11
                                Layout.preferredWidth: 60
                            }
                            Text {
                                text: modelData.active ? "✅" : "❌"
                                color: modelData.active ? successColor : dangerColor
                                font.pixelSize: 12
                            }
                            Text {
                                text: modelData.type
                                color: "gray"
                                font.pixelSize: 10
                            }
                        }
                    }
                }
            }
        }

        // Logs en tiempo real
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: cardColor
            radius: 8
            border.color: "#555"

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 10
                spacing: 6
                Text {
                    text: "📜 Consola de Eventos"
                    color: accentColor
                    font.bold: true
                    font.pixelSize: 14
                }
                ScrollView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    TextEdit {
                        id: logArea
                        color: textColor
                        font.family: "Monospace"
                        font.pixelSize: 12
                        readOnly: true
                        wrapMode: TextEdit.Wrap
                        background: Rectangle {
                            color: "#1a1a1a"
                            radius: 4
                        }
                        onTextChanged: {
                            // Auto-scroll al final
                            var cursor = logArea.cursorPosition
                            logArea.moveCursorToEnd()
                            logArea.cursorPosition = cursor
                        }
                    }
                }
            }
        }
    }
}
