import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Window 2.15

ApplicationWindow {
    id: root
    width: 1024
    height: 720
    visible: true
    title: "🛡️ Antivirus Profesional Linux"
    color: "#1a1a1a"
    
    // Colores del tema
    property color primaryColor: "#00b4d8"
    property color secondaryColor: "#0077b6"
    property color darkBg: "#1a1a1a"
    property color cardBg: "#2d2d2d"
    property color textColor: "#ffffff"
    property color threatColor: "#ff4d4d"
    property color safeColor: "#4caf50"
    
    // Conexión con el backend
    Connections {
        target: backend
        function onScanStarted(message) {
            statusText.text = message
            statusIcon.source = "qrc:/icons/scanning.png"
        }
        function onScanProgress(processed, message) {
            progressBar.value = processed
            statusText.text = message
        }
        function onScanFinished(result) {
            if (result.error) {
                statusText.text = "Error: " + result.error
                statusIcon.source = "qrc:/icons/error.png"
                return
            }
            var msg = "Escaneo completado: " + result.total + " archivos, " + result.infected + " amenazas"
            statusText.text = msg
            statusIcon.source = result.infected > 0 ? "qrc:/icons/warning.png" : "qrc:/icons/ok.png"
            if (result.infected > 0) {
                threatList.addThreats(result.files)
            }
        }
        function onThreatFound(filepath, motivo) {
            threatList.addThreat(filepath, motivo)
            threatBadge.text = parseInt(threatBadge.text) + 1
            notification.show("⚠️ Amenaza detectada", filepath + "\n" + motivo)
        }
        function onQuarantineUpdated(files) {
            quarantineList.model = files
        }
        function onLogUpdated(message) {
            logArea.append(message)
        }
        function onStatusChanged(type, message) {
            statusText.text = message
            if (type === "ok") statusIcon.source = "qrc:/icons/ok.png"
            else if (type === "warning") statusIcon.source = "qrc:/icons/warning.png"
            else if (type === "error") statusIcon.source = "qrc:/icons/error.png"
        }
    }
    
    // ============ HEADER ============
    Rectangle {
        id: header
        height: 70
        color: primaryColor
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        
        RowLayout {
            anchors.fill: parent
            anchors.margins: 10
            spacing: 15
            
            Text {
                text: "🛡️ ANTIVIRUS"
                color: "white"
                font.pixelSize: 24
                font.bold: true
            }
            
            Text {
                text: "PROFESIONAL"
                color: "white"
                font.pixelSize: 18
                opacity: 0.8
                Layout.leftMargin: 5
            }
            
            Item { Layout.fillWidth: true }
            
            // Badge de amenazas
            Rectangle {
                id: threatBadge
                width: 32
                height: 32
                radius: 16
                color: threatColor
                visible: parseInt(text) > 0
                Text {
                    id: threatBadgeText
                    text: "0"
                    anchors.centerIn: parent
                    color: "white"
                    font.bold: true
                    font.pixelSize: 14
                }
            }
            
            Button {
                text: "Actualizar"
                onClicked: backend.update_signatures()
                background: Rectangle {
                    color: parent.pressed ? "#005a8c" : "white"
                    radius: 5
                }
                contentItem: Text {
                    text: parent.text
                    color: parent.pressed ? "white" : primaryColor
                    font.bold: true
                }
            }
        }
    }
    
    // ============ CONTENIDO PRINCIPAL ============
    ColumnLayout {
        anchors.top: header.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: 10
        spacing: 10
        
        // ============ PANEL DE ESTADO ============
        Rectangle {
            id: statusPanel
            Layout.fillWidth: true
            height: 80
            color: cardBg
            radius: 8
            
            RowLayout {
                anchors.fill: parent
                anchors.margins: 10
                spacing: 15
                
                Image {
                    id: statusIcon
                    width: 48
                    height: 48
                    source: "qrc:/icons/idle.png"
                    fillMode: Image.PreserveAspectFit
                }
                
                Column {
                    spacing: 5
                    Layout.fillWidth: true
                    
                    Text {
                        id: statusText
                        text: "Listo"
                        color: textColor
                        font.pixelSize: 16
                        font.bold: true
                    }
                    
                    ProgressBar {
                        id: progressBar
                        width: parent.width
                        value: 0
                        visible: false
                        from: 0
                        to: 100
                        background: Rectangle {
                            color: "#3d3d3d"
                            radius: 3
                        }
                        contentItem: Rectangle {
                            color: primaryColor
                            radius: 3
                            width: progressBar.visible ? progressBar.position * parent.width : 0
                        }
                    }
                }
                
                Button {
                    text: "Iniciar Tiempo Real"
                    onClicked: backend.start_realtime()
                    background: Rectangle {
                        color: parent.pressed ? "#005a8c" : primaryColor
                        radius: 5
                    }
                    contentItem: Text {
                        text: parent.text
                        color: "white"
                        font.bold: true
                    }
                }
            }
        }
        
        // ============ PESTAÑAS ============
        TabBar {
            id: tabBar
            Layout.fillWidth: true
            background: Rectangle { color: cardBg }
            
            TabButton { text: "🔍 Escanear" }
            TabButton { text: "⏰ Programados" }
            TabButton { text: "🗑️ Cuarentena" }
            TabButton { text: "📊 Reportes" }
            TabButton { text: "⚙️ Configuración" }
        }
        
        // ============ STACKVIEW ============
        StackLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            currentIndex: tabBar.currentIndex
            
            // ---------- PESTAÑA ESCANEAR ----------
            Rectangle {
                color: darkBg
                
                GridLayout {
                    anchors.fill: parent
                    anchors.margins: 15
                    columns: 2
                    rows: 4
                    columnSpacing: 15
                    rowSpacing: 15
                    
                    Label { text: "Ruta a escanear:"; color: textColor }
                    
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 5
                        
                        TextField {
                            id: pathInput
                            Layout.fillWidth: true
                            text: "/home/asus/Descargas"
                            color: textColor
                            background: Rectangle {
                                color: "#3d3d3d"
                                radius: 5
                            }
                        }
                        
                        Button {
                            text: "📁"
                            onClicked: {
                                // Aquí iría un diálogo para seleccionar carpeta
                                // Por simplicidad, usamos entrada manual
                            }
                        }
                    }
                    
                    // Botones de escaneo
                    Button {
                        text: "🔍 Escanear Carpeta"
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        onClicked: backend.start_full_scan(pathInput.text)
                        background: Rectangle {
                            color: parent.pressed ? "#005a8c" : primaryColor
                            radius: 5
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            font.bold: true
                            horizontalAlignment: Text.AlignHCenter
                        }
                    }
                    
                    Button {
                        text: "🧠 Escanear Memoria"
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        onClicked: backend.scan_memory()
                        background: Rectangle {
                            color: parent.pressed ? "#6d4c41" : "#8d6e63"
                            radius: 5
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            font.bold: true
                        }
                    }
                    
                    Button {
                        text: "📦 Escanear Comprimido"
                        Layout.columnSpan: 2
                        Layout.fillWidth: true
                        onClicked: {
                            // Diálogo simple para ingresar ruta
                            var dialog = Qt.createQmlObject('
                                import QtQuick.Dialogs 1.3
                                FileDialog {
                                    title: "Seleccionar archivo comprimido"
                                    nameFilters: ["Archivos comprimidos (*.zip *.tar.gz *.rar *.7z)", "Todos (*)"]
                                    onAccepted: {
                                        backend.scan_archive(fileUrl.toString().replace("file://", ""))
                                    }
                                }
                            ', root)
                            dialog.open()
                        }
                        background: Rectangle {
                            color: parent.pressed ? "#2e7d32" : "#388e3c"
                            radius: 5
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            font.bold: true
                        }
                    }
                }
            }
            
            // ---------- PESTAÑA PROGRAMADOS ----------
            Rectangle {
                color: darkBg
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 15
                    spacing: 15
                    
                    Text {
                        text: "⏰ Tareas Programadas"
                        color: textColor
                        font.pixelSize: 20
                        font.bold: true
                    }
                    
                    ListView {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        model: ListModel {
                            id: scheduledModel
                            // Ejemplo de datos - se llenarán desde el backend
                            ListElement { name: "Análisis Completo"; time: "03:00"; active: true; type: "Sistema" }
                            ListElement { name: "Descargas"; time: "14:30"; active: true; type: "Carpeta" }
                            ListElement { name: "Escaneo /tmp"; time: "22:00"; active: true; type: "Carpeta" }
                        }
                        delegate: Rectangle {
                            width: parent.width
                            height: 60
                            color: cardBg
                            radius: 5
                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 10
                                spacing: 10
                                
                                Text {
                                    text: "🕐 " + time
                                    color: active ? textColor : "#666"
                                    font.bold: true
                                }
                                Text {
                                    text: name
                                    color: active ? textColor : "#666"
                                    Layout.fillWidth: true
                                }
                                Text {
                                    text: type
                                    color: "#888"
                                }
                                Button {
                                    text: active ? "✅ Activo" : "❌ Inactivo"
                                    onClicked: {
                                        // Toggle active
                                        var idx = index
                                        // Backend toggle
                                    }
                                    background: Rectangle {
                                        color: active ? "#4caf50" : "#666"
                                        radius: 3
                                    }
                                    contentItem: Text {
                                        text: parent.text
                                        color: "white"
                                        font.pixelSize: 12
                                    }
                                }
                            }
                        }
                    }
                    
                    Button {
                        text: "➕ Agregar Tarea"
                        onClicked: {
                            // Abrir diálogo para agregar
                        }
                        background: Rectangle {
                            color: parent.pressed ? "#005a8c" : primaryColor
                            radius: 5
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            font.bold: true
                        }
                    }
                }
            }
            
            // ---------- PESTAÑA CUARENTENA ----------
            Rectangle {
                color: darkBg
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 15
                    spacing: 15
                    
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 10
                        
                        Text {
                            text: "🗑️ Cuarentena"
                            color: textColor
                            font.pixelSize: 20
                            font.bold: true
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        Button {
                            text: "🔄 Actualizar"
                            onClicked: backend.get_quarantine_list()
                            background: Rectangle {
                                color: parent.pressed ? "#005a8c" : primaryColor
                                radius: 5
                            }
                            contentItem: Text {
                                text: parent.text
                                color: "white"
                            }
                        }
                    }
                    
                    ListView {
                        id: quarantineList
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        model: ListModel { id: quarantineModel }
                        delegate: Rectangle {
                            width: parent.width
                            height: 70
                            color: cardBg
                            radius: 5
                            RowLayout {
                                anchors.fill: parent
                                anchors.margins: 10
                                spacing: 10
                                
                                Column {
                                    Layout.fillWidth: true
                                    spacing: 3
                                    
                                    Text {
                                        text: model.name || "Archivo"
                                        color: textColor
                                        font.bold: true
                                    }
                                    Text {
                                        text: (model.reason || "Sin motivo").substring(0, 80)
                                        color: "#aaa"
                                        font.pixelSize: 12
                                        wrapMode: Text.WordWrap
                                    }
                                    Text {
                                        text: model.date || ""
                                        color: "#666"
                                        font.pixelSize: 10
                                    }
                                }
                                
                                RowLayout {
                                    spacing: 5
                                    
                                    Button {
                                        text: "↩️"
                                        onClicked: backend.restore_quarantine(model.name)
                                        background: Rectangle {
                                            color: parent.pressed ? "#00695c" : "#00897b"
                                            radius: 3
                                        }
                                        contentItem: Text {
                                            text: parent.text
                                            color: "white"
                                        }
                                        ToolTip {
                                            text: "Restaurar archivo"
                                            visible: parent.hovered
                                        }
                                    }
                                    Button {
                                        text: "🗑️"
                                        onClicked: backend.delete_quarantine(model.name)
                                        background: Rectangle {
                                            color: parent.pressed ? "#b71c1c" : "#d32f2f"
                                            radius: 3
                                        }
                                        contentItem: Text {
                                            text: parent.text
                                            color: "white"
                                        }
                                        ToolTip {
                                            text: "Eliminar archivo"
                                            visible: parent.hovered
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // ---------- PESTAÑA REPORTES ----------
            Rectangle {
                color: darkBg
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 15
                    spacing: 15
                    
                    Text {
                        text: "📊 Reportes y Logs"
                        color: textColor
                        font.pixelSize: 20
                        font.bold: true
                    }
                    
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        color: "#1a1a1a"
                        radius: 5
                        border.color: "#3d3d3d"
                        border.width: 1
                        
                        ScrollView {
                            anchors.fill: parent
                            anchors.margins: 5
                            
                            TextArea {
                                id: logArea
                                text: "=== Log del Antivirus ===\n"
                                color: "#e0e0e0"
                                font.family: "Monospace"
                                font.pixelSize: 12
                                wrapMode: TextEdit.WordWrap
                                readOnly: true
                                background: Rectangle { color: "transparent" }
                                
                                function append(message) {
                                    var timestamp = new Date().toLocaleString()
                                    text += "[" + timestamp + "] " + message + "\n"
                                    // Scroll al final
                                    cursorPosition = text.length
                                }
                            }
                        }
                    }
                    
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 10
                        
                        Button {
                            text: "🗑️ Limpiar Log"
                            onClicked: logArea.text = "=== Log del Antivirus ===\n"
                            background: Rectangle {
                                color: parent.pressed ? "#c62828" : "#d32f2f"
                                radius: 5
                            }
                            contentItem: Text {
                                text: parent.text
                                color: "white"
                            }
                        }
                        
                        Item { Layout.fillWidth: true }
                        
                        Button {
                            text: "💾 Exportar Log"
                            onClicked: {
                                // Exportar a archivo
                            }
                            background: Rectangle {
                                color: parent.pressed ? "#005a8c" : primaryColor
                                radius: 5
                            }
                            contentItem: Text {
                                text: parent.text
                                color: "white"
                            }
                        }
                    }
                }
            }
            
            // ---------- PESTAÑA CONFIGURACIÓN ----------
            Rectangle {
                color: darkBg
                
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 15
                    spacing: 15
                    
                    Text {
                        text: "⚙️ Configuración"
                        color: textColor
                        font.pixelSize: 20
                        font.bold: true
                    }
                    
                    GridLayout {
                        columns: 2
                        columnSpacing: 15
                        rowSpacing: 10
                        Layout.fillWidth: true
                        
                        Label { text: "Cuarentena:"; color: textColor }
                        TextField {
                            text: "./cuarentena"
                            color: textColor
                            background: Rectangle {
                                color: "#3d3d3d"
                                radius: 5
                            }
                            Layout.fillWidth: true
                        }
                        
                        Label { text: "Máximo de firmas:"; color: textColor }
                        SpinBox {
                            from: 10000
                            to: 1000000
                            stepSize: 10000
                            value: 300000
                            Layout.fillWidth: true
                        }
                        
                        Label { text: "Actualizar firmas al inicio:"; color: textColor }
                        CheckBox { checked: true }
                        
                        Label { text: "Tiempo real activo:"; color: textColor }
                        CheckBox { checked: true }
                    }
                    
                    Button {
                        text: "💾 Guardar Configuración"
                        Layout.alignment: Qt.AlignHCenter
                        onClicked: {
                            // Guardar configuración
                        }
                        background: Rectangle {
                            color: parent.pressed ? "#005a8c" : primaryColor
                            radius: 5
                        }
                        contentItem: Text {
                            text: parent.text
                            color: "white"
                            font.bold: true
                        }
                    }
                }
            }
        }
    }
    
    // ============ NOTIFICACIÓN FLOTANTE ============
    Rectangle {
        id: notification
        visible: false
        width: 400
        height: 80
        color: "#323232"
        radius: 8
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 30
        anchors.horizontalCenter: parent.horizontalCenter
        
        property string title: ""
        property string message: ""
        
        function show(title, message) {
            notification.title = title
            notification.message = message
            notification.visible = true
            timer.start()
        }
        
        Timer {
            id: timer
            interval: 5000
            onTriggered: notification.visible = false
        }
        
        RowLayout {
            anchors.fill: parent
            anchors.margins: 15
            spacing: 15
            
            Image {
                width: 32
                height: 32
                source: "qrc:/icons/warning.png"
                fillMode: Image.PreserveAspectFit
            }
            
            Column {
                Layout.fillWidth: true
                spacing: 3
                
                Text {
                    text: notification.title
                    color: "white"
                    font.bold: true
                    font.pixelSize: 14
                }
                Text {
                    text: notification.message
                    color: "#cccccc"
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }
            }
            
            Button {
                text: "✕"
                onClicked: {
                    notification.visible = false
                    timer.stop()
                }
                background: Rectangle {
                    color: "transparent"
                }
                contentItem: Text {
                    text: parent.text
                    color: "white"
                }
            }
        }
    }
}
