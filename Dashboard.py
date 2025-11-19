import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, 
    QWidget, QFileDialog, QTableWidget, QTableWidgetItem,
    QTextEdit, QSplitter, QHeaderView, QLabel, QFrame, QGridLayout,
    QMessageBox, QAbstractItemView, QSlider, QComboBox, QToolTip
)
from PySide6.QtCore import Qt, QSize, QTimer, QMargins
from PySide6.QtGui import QColor, QFont, QPalette, QCursor, QPainter

# --- IMPORTACIONES DE GRÁFICOS ---
from PySide6.QtCharts import QChart, QChartView, QPieSeries, QPieSlice

# Importamos nuestro motor y exportador
from active_inventory_generator import parse_nmap_xml, get_cvss_rating_and_color
from excel_exporter import create_report 

# --- ESTILO QSS (CSS para Qt) ---
DARK_THEME_QSS = """
    QWidget {
        background-color: #1e1e2f; 
        color: #d9d9e0; 
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    QMainWindow {
        background-color: #1e1e2f;
    }
    QFrame#SummaryCard {
        background-color: #27293d;
        border-radius: 8px;
    }
    QTextEdit {
        background-color: #27293d;
        border: 1px solid #3b3f5c;
        border-radius: 4px;
        font-size: 14px;
    }
    QTableWidget {
        background-color: #27293d;
        border: 1px solid #3b3f5c;
        gridline-color: #3b3f5c;
    }
    QTableWidget::item:selected {
        background-color: #122085; 
        color: #ffffff; 
        font-weight: bold;
    }
    QHeaderView::section {
        background-color: #3b3f5c;
        color: #d9d9e0;
        padding: 4px;
        border: none;
        font-weight: bold;
    }
    QPushButton {
        background-color: #5d5fef; 
        color: white;
        font-weight: bold;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
    }
    QPushButton:hover {
        background-color: #7a7cff;
    }
    QPushButton:checked {
        background-color: #28a745; 
        border: 2px solid #28a745; 
    }
    QPushButton:checked:hover {
        background-color: #38c755;
    }
    QLabel#CardTitle {
        font-size: 14px;
        font-weight: bold;
        color: #a0a0b8; 
    }
    QLabel#CardValue {
        font-size: 32px;
        font-weight: bold;
        color: #ffffff;
    }
    QLabel#CveLabel {
        color: white;
        font-weight: bold;
        padding: 5px 10px;
        border-radius: 4px;
        font-size: 13px;
    }
    QSlider::groove:horizontal {
        height: 8px;
        background: #3b3f5c;
        margin: 2px 0;
        border-radius: 4px;
    }
    QSlider::handle:horizontal {
        background: #5d5fef;
        border: 1px solid #5d5fef;
        width: 14px;
        height: 14px;
        margin: -4px 0;
        border-radius: 7px;
    }
    QSlider::sub-page:horizontal {
        background: #7a7cff;
        border-radius: 4px;
    }
    QComboBox {
        background-color: #27293d;
        border: 1px solid #3b3f5c;
        padding: 5px;
        border-radius: 4px;
    }
"""

class NumericTableWidgetItem(QTableWidgetItem):
    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return super().__lt__(other)

class DashboardApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Dashboard de Inventario Nmap")
        self.setGeometry(100, 100, 1400, 900)
        self.hosts_data = []
        self.current_xml_path = None 
        self.original_headers = ["IP", "Sistema Operativo", "Criticidad"]
        self.unique_services = set()
        
        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self.apply_filters)
        
        self.setStyleSheet(DARK_THEME_QSS)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setSpacing(15)

        # 1. Botones
        button_container = QWidget()
        button_layout = QHBoxLayout(button_container)
        button_layout.setContentsMargins(0, 0, 0, 0)
        
        self.load_button = QPushButton("Cargar archivo XML de Nmap")
        self.load_button.clicked.connect(self.load_xml_file)
        self.load_button.setFixedWidth(250)
        button_layout.addWidget(self.load_button)
        
        self.export_button = QPushButton("Exportar a Excel")
        self.export_button.clicked.connect(self.export_to_excel)
        self.export_button.setEnabled(False) 
        self.export_button.setFixedWidth(250)
        button_layout.addWidget(self.export_button)

        button_layout.addStretch() 
        main_layout.addWidget(button_container)

        # 2. Panel Superior (Resumen)
        summary_panel = self._create_summary_panel()
        main_layout.addWidget(summary_panel)

        # 3. Panel Principal (Tabla y Detalles)
        main_panel = self._create_main_panel()
        main_layout.addWidget(main_panel, 1)

    def _create_summary_panel(self):
        container = QWidget()
        layout = QVBoxLayout(container) 
        layout.setSpacing(10) 
        layout.setContentsMargins(5, 5, 5, 5)

        # --- FILA 0: COMANDO ---
        self.nmap_command_label = QLabel("Nmap command...")
        self.nmap_command_label.setStyleSheet("color: #a0a0b8; font-family: 'Courier New'; font-size: 12px;")
        self.nmap_command_label.setWordWrap(True)
        layout.addWidget(self.nmap_command_label)

        # --- FILA 1: DATA ROW (Métricas + CVEs + Gráfico) ---
        data_row = QHBoxLayout()
        data_row.setSpacing(20)

        # [COLUMNA IZQUIERDA] Contiene: Fila de Métricas y debajo Fila de CVEs
        left_column = QVBoxLayout()
        left_column.setSpacing(15)

        # 1.1 Fila de Métricas (Assets, Services, Ports)
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(10)
        
        self.scanned_assets_label = QLabel("0")
        card_assets = self._create_card("Assets", self.scanned_assets_label)
        metrics_row.addWidget(card_assets)

        self.services_label = QLabel("0")
        card_services = self._create_card("Services", self.services_label)
        metrics_row.addWidget(card_services)

        self.ports_label = QLabel("0")
        card_ports = self._create_card("Ports", self.ports_label)
        metrics_row.addWidget(card_ports)
        
        left_column.addLayout(metrics_row)

        # 1.2 Fila de CVEs (Horizontal debajo de las métricas)
        cves_row = QHBoxLayout()
        cves_row.setSpacing(10)
        
        self.cve_critical_label = QLabel("Critical 0")
        self.cve_critical_label.setObjectName("CveLabel")
        self.cve_critical_label.setStyleSheet("background-color: #d9534f; font-size: 12px;")
        self.cve_critical_label.setAlignment(Qt.AlignCenter)
        self.cve_critical_label.setFixedHeight(40) 
        
        self.cve_high_label = QLabel("High 0")
        self.cve_high_label.setObjectName("CveLabel")
        self.cve_high_label.setStyleSheet("background-color: #f0ad4e; font-size: 12px;")
        self.cve_high_label.setAlignment(Qt.AlignCenter)
        self.cve_high_label.setFixedHeight(40)
        
        self.cve_medium_label = QLabel("Medium 0")
        self.cve_medium_label.setObjectName("CveLabel")
        self.cve_medium_label.setStyleSheet("background-color: #b66dff; font-size: 12px;")
        self.cve_medium_label.setAlignment(Qt.AlignCenter)
        self.cve_medium_label.setFixedHeight(40)
        
        self.cve_low_label = QLabel("Low 0")
        self.cve_low_label.setObjectName("CveLabel")
        self.cve_low_label.setStyleSheet("background-color: #777777; font-size: 12px;")
        self.cve_low_label.setAlignment(Qt.AlignCenter)
        self.cve_low_label.setFixedHeight(40)

        cves_row.addWidget(self.cve_critical_label, 1)
        cves_row.addWidget(self.cve_high_label, 1)
        cves_row.addWidget(self.cve_medium_label, 1)
        cves_row.addWidget(self.cve_low_label, 1)

        cve_container = QFrame()
        cve_container.setObjectName("SummaryCard")
        cve_container_layout = QVBoxLayout(cve_container)
        cve_container_layout.setContentsMargins(10, 10, 10, 10)
        
        lbl_cve_title = QLabel("Detected Vulnerabilities")
        lbl_cve_title.setStyleSheet("color: #a0a0b8; font-size: 11px; font-weight: bold;")
        cve_container_layout.addWidget(lbl_cve_title)
        cve_container_layout.addLayout(cves_row)
        
        left_column.addWidget(cve_container)
        data_row.addLayout(left_column, 4) 

        # [COLUMNA DERECHA] GRÁFICO DE TARTA
        chart_container = QWidget()
        chart_layout = QVBoxLayout(chart_container)
        chart_layout.setContentsMargins(0, 0, 0, 0)
        
        title_os = QLabel("OS Families")
        title_os.setStyleSheet("font-weight: bold; color: #a0a0b8; font-size: 14px;")
        title_os.setAlignment(Qt.AlignCenter)
        chart_layout.addWidget(title_os)

        self.os_pie_series = QPieSeries()
        self.os_pie_series.hovered.connect(self.on_pie_slice_hovered)
        
        self.chart = QChart()
        self.chart.addSeries(self.os_pie_series)
        
        # --- ¡CAMBIO! LEYENDA ACTIVADA ---
        self.chart.legend().setVisible(True)
        self.chart.legend().setAlignment(Qt.AlignRight)
        self.chart.legend().setLabelColor(QColor("#d9d9e0"))
        self.chart.legend().setFont(QFont("Segoe UI", 9))
        self.chart.legend().setBackgroundVisible(False)
        # ---------------------------------

        self.chart.setBackgroundRoundness(0)
        self.chart.setMargins(QMargins(0, 0, 0, 0))
        self.chart.layout().setContentsMargins(0, 0, 0, 0)
        self.chart.setBackgroundBrush(Qt.NoBrush)

        self.chart_view = QChartView(self.chart)
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        self.chart_view.setStyleSheet("background: transparent;")
        self.chart_view.setMinimumHeight(180) 
        
        chart_layout.addWidget(self.chart_view)
        
        data_row.addWidget(chart_container, 5) 

        layout.addLayout(data_row)

        # --- FILA 2: FILTROS ---
        filters_layout = QHBoxLayout()
        
        self.cvss_label = QLabel("CVSS > 0.0")
        self.cvss_label.setStyleSheet("font-weight: bold; color: #a0a0b8; margin-right: 5px;")
        self.cvss_slider = QSlider(Qt.Horizontal)
        self.cvss_slider.setRange(0, 100)
        self.cvss_slider.setFixedWidth(150) 
        self.cvss_slider.valueChanged.connect(self._update_cvss_label)
        self.cvss_slider.sliderReleased.connect(self.filter_timer.start)
        
        filters_layout.addWidget(self.cvss_label)
        filters_layout.addWidget(self.cvss_slider)
        filters_layout.addSpacing(20)

        filters_layout.addWidget(QLabel("Servicio:"))
        self.service_combo = QComboBox()
        self.service_combo.addItem("Todos")
        self.service_combo.setMinimumWidth(150)
        self.service_combo.currentTextChanged.connect(self.apply_filters)
        filters_layout.addWidget(self.service_combo)
        filters_layout.addStretch() 
        
        filters_layout.addWidget(QLabel("Puertos:"))
        self.common_ports = {
            "SMB": [139, 445], "RDP": [3389], "DB": [1433, 3306, 5432],
            "SSH": [22, 23], "WEB": [80, 443]
        }
        self.port_buttons = {}
        for name, ports in self.common_ports.items():
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.setToolTip(f"Puertos: {', '.join(map(str, ports))}")
            btn.setFixedWidth(60) 
            btn.clicked.connect(self.apply_filters)
            self.port_buttons[name] = btn
            filters_layout.addWidget(btn)

        layout.addLayout(filters_layout)

        return container

    def on_pie_slice_hovered(self, slice, state):
        if state:
            slice.setExploded(True)
            # Solo tooltip, sin etiqueta sobre el queso
            info_text = f"{int(slice.value())} {slice.label()}"
            QToolTip.showText(QCursor.pos(), info_text)
        else:
            slice.setExploded(False)
            slice.setLabelVisible(False)
            QToolTip.hideText()

    def _update_cvss_label(self, value):
        cvss_value = value / 10.0
        self.cvss_label.setText(f"CVSS > {cvss_value:.1f}")

    def _create_card(self, title_text, value_widget):
        card = QFrame()
        card.setObjectName("SummaryCard")
        
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(15, 15, 15, 15)
        
        title_label = QLabel(title_text)
        title_label.setObjectName("CardTitle")
        title_label.setAlignment(Qt.AlignCenter)
        
        if isinstance(value_widget, QLabel):
            value_widget.setObjectName("CardValue")
            value_widget.setAlignment(Qt.AlignCenter)
        
        card_layout.addWidget(title_label)
        card_layout.addWidget(value_widget)
        
        return card

    def _create_main_panel(self):
        splitter = QSplitter(Qt.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("Hosts Descubiertos"))
        
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(3)
        self.reset_header_labels()
        
        self.hosts_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.hosts_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.hosts_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        
        self.hosts_table.cellClicked.connect(self.show_host_details)
        self.hosts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        
        self.hosts_table.setSortingEnabled(True)
        self.hosts_table.horizontalHeader().sortIndicatorChanged.connect(self.update_header_labels)
        self.hosts_table.setSelectionBehavior(QAbstractItemView.SelectRows)

        # Anular color de selección azul
        palette = self.hosts_table.palette()
        palette.setColor(QPalette.Highlight, QColor(0, 0, 0, 0)) 
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        self.hosts_table.setPalette(palette)

        left_layout.addWidget(self.hosts_table)
        splitter.addWidget(left_panel)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.addWidget(QLabel("Detalles del Host Seleccionado"))

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Courier New", 10))
        
        right_layout.addWidget(self.details_text)
        splitter.addWidget(right_panel)

        splitter.setSizes([700, 700])
        return splitter

    def reset_header_labels(self):
        labels_with_arrow = [f"{text} ▶️" for text in self.original_headers]
        self.hosts_table.setHorizontalHeaderLabels(labels_with_arrow)

    def update_header_labels(self, column_index, order):
        for i, text in enumerate(self.original_headers):
            item = self.hosts_table.horizontalHeaderItem(i)
            if item is None:
                item = QTableWidgetItem()
                self.hosts_table.setHorizontalHeaderItem(i, item)

            arrow = " ▶️"
            if i == column_index:
                arrow = " 🔼" if order == Qt.AscendingOrder else " 🔽"
            
            item.setText(text + arrow)

    def load_xml_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Abrir XML", "", "Archivos XML (*.xml)")
        if file_path:
            self.current_xml_path = file_path 
            self.parse_and_load_data(file_path)

    def parse_and_load_data(self, xml_file):
        self.hosts_table.setSortingEnabled(False)
        self.hosts_data = []
        self.unique_services = set()
        self.hosts_table.setRowCount(0)
        self.reset_header_labels() 
        self.os_pie_series.clear() 

        try:
            summary_data, hosts_list = parse_nmap_xml(xml_file)
            self.hosts_data = hosts_list 

            self.nmap_command_label.setText(summary_data['nmap_command'])
            self.scanned_assets_label.setText(str(summary_data['scanned_assets']))
            self.services_label.setText(str(summary_data['services']))
            self.ports_label.setText(str(summary_data['ports']))

            # --- LLENAR GRÁFICO DE TARTA ---
            os_families = summary_data.get('os_families', {})
            colors = [
                "#5d5fef", "#f0ad4e", "#d9534f", "#b66dff", "#5bc0de", 
                "#5cb85c", "#f7f7f7", "#e83e8c", "#fd7e14", "#20c997"
            ]
            
            if os_families:
                sorted_os = sorted(os_families.items(), key=lambda x: x[1], reverse=True)
                for i, (os_name, count) in enumerate(sorted_os):
                    _slice = self.os_pie_series.append(os_name, count)
                    _slice.setColor(QColor(colors[i % len(colors)]))
                    _slice.setLabelVisible(False) 
            else:
                _slice = self.os_pie_series.append("Sin Datos", 1)
                _slice.setColor(QColor("#777777"))
            # --------------------------------

            # Recolectar servicios únicos
            for host in self.hosts_data:
                if host['ports']:
                    for _, service_name, _, _ in host['ports']:
                        self.unique_services.add(service_name)
            
            self.service_combo.blockSignals(True)
            self.service_combo.clear()
            self.service_combo.addItem("Todos") 
            self.service_combo.addItems(sorted(list(self.unique_services)))
            self.service_combo.blockSignals(False)

            cve_counts = summary_data['cve_counts']
            self.cve_critical_label.setText(f"Critical {cve_counts['Critical']}")
            self.cve_high_label.setText(f"High {cve_counts['High']}")
            self.cve_medium_label.setText(f"Medium {cve_counts['Medium']}")
            self.cve_low_label.setText(f"Low {cve_counts['Low']}")

            self.load_table_data(self.hosts_data)
            
            self.export_button.setEnabled(True)
            self.details_text.setText("Datos cargados. Selecciona un host para ver detalles.")

        except Exception as e:
            self.hosts_data = [] 
            self.hosts_table.setRowCount(0)
            self.export_button.setEnabled(False) 
            error_msg = f"Error al procesar el archivo XML:\n{e}\n\nAsegúrate de que es un XML de Nmap válido."
            self.details_text.setText(error_msg)
            QMessageBox.critical(self, "Error de Análisis", error_msg)
            print(f"Error: {e}") 
        
        self.hosts_table.setSortingEnabled(True)

    def load_table_data(self, data_list):
        self.hosts_table.setSortingEnabled(False)
        self.hosts_table.setRowCount(len(data_list))
        
        for i, host_info in enumerate(data_list):
            ip_item = QTableWidgetItem(host_info['ip'])
            ip_item.setData(Qt.UserRole, self.hosts_data.index(host_info)) 
            
            os_item = QTableWidgetItem(host_info['os'])
            cvss_item = NumericTableWidgetItem(str(host_info['max_cvss']))
            
            rating, (r, g, b) = get_cvss_rating_and_color(host_info['max_cvss'])
            row_color = QColor(r, g, b, 100)
            
            for item in (ip_item, os_item, cvss_item):
                item.setBackground(row_color)

            self.hosts_table.setItem(i, 0, ip_item)
            self.hosts_table.setItem(i, 1, os_item)
            self.hosts_table.setItem(i, 2, cvss_item)

        self.hosts_table.setSortingEnabled(True)

    def apply_filters(self):
        if not self.hosts_data:
            return

        min_cvss = self.cvss_slider.value() / 10.0
        selected_service = self.service_combo.currentText()
        
        active_ports = []
        active_port_names = []
        for name, btn in self.port_buttons.items():
            if btn.isChecked():
                active_ports.extend(self.common_ports[name])
                active_port_names.append(name)
        
        filtered_hosts = []

        for host in self.hosts_data:
            cvss_pass = True
            service_pass = True
            port_pass = True 

            if float(host['max_cvss']) < min_cvss:
                cvss_pass = False

            if selected_service != "Todos":
                service_pass = False 
                for _, service_name, _, _ in host['ports']:
                    if service_name == selected_service:
                        service_pass = True
                        break

            if active_ports: 
                port_pass = False 
                host_ports = []
                try:
                    host_ports = [int(p[0]) for p in host['ports']] 
                except ValueError:
                    host_ports = [] 
                
                for required_port in active_ports:
                    if required_port in host_ports: 
                        port_pass = True
                        break 

            if cvss_pass and service_pass and port_pass: 
                filtered_hosts.append(host)

        self.load_table_data(filtered_hosts)
        
        details_text = f"Filtrado aplicado:\n"
        details_text += f"- CVSS Mínimo: {min_cvss:.1f}\n"
        details_text += f"- Servicio: {selected_service}\n"
        details_text += f"- Puertos Activos: {', '.join(active_port_names) if active_port_names else 'Ninguno'}\n"
        details_text += f"\nMostrando {len(filtered_hosts)} de {len(self.hosts_data)} hosts."
        self.details_text.setText(details_text)

    def show_host_details(self, row, column):
        ip_item = self.hosts_table.item(row, 0)
        if ip_item is None:
            return
        
        try:
            original_index = ip_item.data(Qt.UserRole)
            host_info = self.hosts_data[original_index]
        except Exception as e:
            print(f"Error al obtener detalles del host: {e}")
            return
        
        details_str = f"--- Información del Host ---\n"
        details_str += f"IP: {host_info['ip']}\n"
        details_str += f"Sistema Operativo: {host_info['os']}\n"
        details_str += f"Criticidad Máxima: {host_info['max_cvss']}\n"
        
        details_str += "\n--- Puertos y Servicios ---\n"
        if host_info['ports']:
            for port_id, service, product, version in host_info['ports']:
                service_detail = service
                if product:
                    service_detail += f" ({product}"
                    if version:
                        service_detail += f" {version})"
                    else:
                        service_detail += ")"
                        
                details_str += f"   - Puerto: {port_id:<5} Servicio: {service_detail}\n"
        else:
            details_str += "   (No hay puertos abiertos detectados)\n"
            
        details_str += "\n--- Vulnerabilidades ---\n"
        if host_info['vulnerabilities']:
            sorted_vulns = sorted(host_info['vulnerabilities'], key=lambda v: float(v['cvss']) if v['cvss'].replace('.', '', 1).isdigit() else 0.0, reverse=True)
            
            for vuln in sorted_vulns:
                cvss_score = vuln['cvss']
                rating, color = get_cvss_rating_and_color(cvss_score)
                
                details_str += f"   - Nombre: {vuln['name']}\n"
                details_str += f"     Criticidad: {cvss_score} ({rating})\n"
                details_str += f"     Puerto: {vuln['port']} ({vuln['service']})\n"
                details_str += f"     CVEs: {', '.join(vuln['cve'])}\n"
                
                desc = vuln.get('description', 'N/A')
                if desc is None: desc = "N/A"
                details_str += f"     Descripción: {desc[:100]}...\n" 
                
                refs = vuln.get('references', [])
                if refs:
                    details_str += f"     Referencias: {', '.join(refs[:2])}...\n"
                
                details_str += "\n"
        else:
            details_str += "   (No se encontraron vulnerabilidades)\n"

        self.details_text.setText(details_str)

    def export_to_excel(self):
        if not self.hosts_data:
            QMessageBox.warning(self, "Sin datos", "No hay datos cargados para exportar.")
            return

        default_name = "nmap_report.xlsx"
        if self.current_xml_path:
            base_name = self.current_xml_path.split('/')[-1].replace('.xml', '')
            default_name = f"{base_name}_report.xlsx"

        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Guardar Reporte Excel", 
            default_name, 
            "Archivos Excel (*.xlsx)"
        )
        
        if file_path:
            try:
                success, error_msg = create_report(self.hosts_data, file_path)
                
                if success:
                    QMessageBox.information(self, "Éxito", f"Reporte guardado exitosamente en:\n{file_path}")
                else:
                    raise Exception(error_msg)
                    
            except Exception as e:
                QMessageBox.critical(self, "Error de Exportación", f"No se pudo guardar el archivo Excel:\n\n{e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DashboardApp()
    window.show()
    sys.exit(app.exec())
