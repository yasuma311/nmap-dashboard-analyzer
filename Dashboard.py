import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, 
    QWidget, QFileDialog, QTableWidget, QTableWidgetItem,
    QTextEdit, QSplitter, QHeaderView, QLabel, QFrame, QGridLayout,
    QMessageBox, QAbstractItemView, QSlider, QComboBox
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont, QPalette # QPalette para solucionar selección
from PySide6.QtCore import QTimer

# Importamos la nueva función principal de nuestro motor
from active_inventory_generator import parse_nmap_xml, get_cvss_rating_and_color
# ¡Importamos el nuevo exportador!
from excel_exporter import create_report 

# --- ESTILO QSS (CSS para Qt) para el TEMA OSCURO ---
# --- ESTILO QSS (CSS para Qt) para el TEMA OSCURO ---
DARK_THEME_QSS = """
    QWidget {
        background-color: #1e1e2f; /* Fondo principal oscuro */
        color: #d9d9e0; /* Texto principal claro */
        font-family: 'Segoe UI', Arial, sans-serif;
    }
    QMainWindow {
        background-color: #1e1e2f;
    }
    /* Estilo de las "Tarjetas" del dashboard */
    QFrame#SummaryCard {
        background-color: #27293d;
        border-radius: 8px;
    }
    /* Estilo del panel de detalles */
    QTextEdit {
        background-color: #27293d;
        border: 1px solid #3b3f5c;
        border-radius: 4px;
        font-size: 14px;
    }
    /* Estilo de la Tabla */
    QTableWidget {
        background-color: #27293d;
        border: 1px solid #3b3f5c;
        gridline-color: #3b3f5c;
    }
    
    /* Estilo que el usuario dejó: Color sólido en selección */
    QTableWidget::item:selected {
        background-color: #122085; /* Color sólido para la selección */
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
    /* Botón */
    QPushButton {
        background-color: #5d5fef; /* Azul/Violeta */
        color: white;
        font-weight: bold;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
    }
    QPushButton:hover {
        background-color: #7a7cff;
    }
    /* NUEVO: Estilo para botones checkable (como los de puertos) cuando están ACTIVOS */
    QPushButton:checked {
        background-color: #28a745; /* Verde fuerte (Indicador de filtro activo) */
        border: 2px solid #28a745; 
    }
    QPushButton:checked:hover {
        background-color: #38c755;
    }
    /* Etiquetas de Título (ej. "Scanned Assets") */
    QLabel#CardTitle {
        font-size: 14px;
        font-weight: bold;
        color: #a0a0b8; /* Color de texto secundario */
    }
    /* Etiquetas de Valor (ej. "100") */
    QLabel#CardValue {
        font-size: 32px;
        font-weight: bold;
        color: #ffffff;
    }
    /* Etiquetas de Criticidad */
    QLabel#CveLabel {
        color: white;
        font-weight: bold;
        padding: 5px 10px;
        border-radius: 4px;
        font-size: 13px;
    }
    /* Estilo del Slider CVSS */
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
    /* Estilo del ComboBox de Servicios */
    QComboBox {
        background-color: #27293d;
        border: 1px solid #3b3f5c;
        padding: 5px;
        border-radius: 4px;
    }
"""

# --- ¡NUEVA CLASE PARA ORDENAR NÚMEROS! ---
class NumericTableWidgetItem(QTableWidgetItem):
    """
    Un QTableWidgetItem personalizado que se ordena numéricamente
    en lugar de alfabéticamente.
    """
    def __lt__(self, other):
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return super().__lt__(other)

# --- FIN DE LA NUEVA CLASE ---


class DashboardApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nmap Dashboard Analyzer")
        self.setGeometry(100, 100, 1400, 900)
        self.hosts_data = []
        self.current_xml_path = None 
        self.original_headers = ["IP", "Sistema Operativo", "Criticidad"]
        self.unique_services = [] # Lista de servicios únicos para el filtro
        
        # QTimer para retrasar el filtro de CVSS (mejor rendimiento)
        self.filter_timer = QTimer(self)
        self.filter_timer.setSingleShot(True)
        self.filter_timer.timeout.connect(self.apply_filters)
        
        self.setStyleSheet(DARK_THEME_QSS)

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setSpacing(15)

        # 1. Panel de Botones (Superior)
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

        # 2. Panel de Resumen (Las Tarjetas) y Filtrado
        summary_panel = self._create_summary_panel()
        main_layout.addWidget(summary_panel)

        # 3. Panel Principal (Tabla y Detalles)
        main_panel = self._create_main_panel()
        main_layout.addWidget(main_panel, 1)

    def _create_summary_panel(self):
        """Crea el widget superior con las tarjetas de estadísticas y los filtros."""
        container = QWidget()
        layout = QGridLayout(container)
        layout.setSpacing(15)

        self.nmap_command_label = QLabel("Nmap command will appear here...")
        self.nmap_command_label.setStyleSheet("color: #a0a0b8; font-family: 'Courier New', monospace; font-size: 13px;")
        self.nmap_command_label.setWordWrap(True)
        layout.addWidget(self.nmap_command_label, 0, 0, 1, 6) 

        # --- Fila 1: Tarjetas de Resumen ---
        self.scanned_assets_label = QLabel("0")
        card_assets = self._create_card("Scanned Assets", self.scanned_assets_label)
        layout.addWidget(card_assets, 1, 0) 

        self.os_families_label = QLabel("-")
        self.os_families_label.setObjectName("CardValue")
        self.os_families_label.setStyleSheet("font-size: 16px; font-weight: normal; margin-top: 5px;")
        card_os = self._create_card("OS Families", self.os_families_label)
        layout.addWidget(card_os, 1, 1)

        self.services_label = QLabel("0")
        card_services = self._create_card("Services", self.services_label)
        layout.addWidget(card_services, 1, 2)

        self.ports_label = QLabel("0")
        card_ports = self._create_card("Ports", self.ports_label)
        layout.addWidget(card_ports, 1, 3)

        cve_widget = QWidget()
        cve_layout = QHBoxLayout(cve_widget)
        cve_layout.setContentsMargins(0, 0, 0, 0)
        cve_layout.setSpacing(10)
        
        self.cve_critical_label = QLabel("Critical 0")
        self.cve_critical_label.setObjectName("CveLabel")
        self.cve_critical_label.setStyleSheet("background-color: #d9534f;")
        
        self.cve_high_label = QLabel("High 0")
        self.cve_high_label.setObjectName("CveLabel")
        self.cve_high_label.setStyleSheet("background-color: #f0ad4e;")
        
        self.cve_medium_label = QLabel("Medium 0")
        self.cve_medium_label.setObjectName("CveLabel")
        self.cve_medium_label.setStyleSheet("background-color: #b66dff;") 
        
        self.cve_low_label = QLabel("Low 0")
        self.cve_low_label.setObjectName("CveLabel")
        self.cve_low_label.setStyleSheet("background-color: #777777;") 

        cve_layout.addWidget(self.cve_critical_label)
        cve_layout.addWidget(self.cve_high_label)
        cve_layout.addWidget(self.cve_medium_label)
        cve_layout.addWidget(self.cve_low_label)

        card_cves = self._create_card("Detected CVEs", cve_widget)
        layout.addWidget(card_cves, 1, 4, 1, 2)

        # --- Fila 2: Controles de Filtrado (CVSS y Servicio) ---
        
        # 1. Filtro CVSS
        cvss_filter_widget = QWidget()
        cvss_filter_layout = QVBoxLayout(cvss_filter_widget)
        cvss_filter_layout.setContentsMargins(0, 0, 0, 0)
        
        self.cvss_label = QLabel("CVSS Mínimo: 0.0")
        self.cvss_slider = QSlider(Qt.Horizontal)
        self.cvss_slider.setRange(0, 100) # De 0.0 a 10.0 con una precisión
        self.cvss_slider.setValue(0)
        self.cvss_slider.setSingleStep(1)
        self.cvss_slider.setTickPosition(QSlider.TicksBelow)
        self.cvss_slider.setTickInterval(10) # Marca cada 1.0 (10 ticks)
        
        self.cvss_slider.valueChanged.connect(self._update_cvss_label)
        self.cvss_slider.sliderReleased.connect(self.filter_timer.start) 
        
        cvss_filter_layout.addWidget(self.cvss_label)
        cvss_filter_layout.addWidget(self.cvss_slider)

        layout.addWidget(cvss_filter_widget, 2, 0, 1, 3) # Ocupa 3 columnas

        # 2. Filtro de Servicios
        service_filter_widget = QWidget()
        service_filter_layout = QVBoxLayout(service_filter_widget)
        service_filter_layout.setContentsMargins(0, 0, 0, 0)
        
        service_filter_layout.addWidget(QLabel("Filtrar por Nombre de Servicio:"))
        self.service_combo = QComboBox()
        self.service_combo.addItem("Mostrar Todos los Servicios")
        self.service_combo.setMinimumWidth(200)
        
        self.service_combo.currentTextChanged.connect(self.apply_filters)
        
        service_filter_layout.addWidget(self.service_combo)
        service_filter_layout.addStretch()

        layout.addWidget(service_filter_widget, 2, 3, 1, 3) # Ocupa 3 columnas restantes
        
        # --- Fila 3: Botones de Puertos Comunes Explotables ---
        port_filter_widget = QWidget()
        port_filter_layout = QHBoxLayout(port_filter_widget)
        port_filter_layout.setContentsMargins(0, 0, 0, 0)
        port_filter_layout.addWidget(QLabel("Puertos Comunes:"))
        
        # Definimos los puertos de interés y creamos los botones
        self.common_ports = {
            "SMB": [139, 445],      # EternalBlue, etc.
            "RDP": [3389],          # Acceso remoto
            "DB": [1433, 3306, 5432], # MSSQL, MySQL, PostgreSQL
            "SSH/TELNET": [22, 23], # Credenciales débiles
        }
        self.port_buttons = {} # Diccionario para guardar referencias a los botones
        
        for name, ports in self.common_ports.items():
            btn = QPushButton(f"{name} ({'/'.join(map(str, ports))})")
            btn.setCheckable(True)
            btn.clicked.connect(self.apply_filters)
            self.port_buttons[name] = btn
            port_filter_layout.addWidget(btn)
            
        port_filter_layout.addStretch()
        
        layout.addWidget(port_filter_widget, 3, 0, 1, 6) # Fila 3, ocupa todo el ancho

        # Ajustamos las filas 
        layout.setRowStretch(1, 1)

        return container

    def _update_cvss_label(self, value):
        """Actualiza la etiqueta CVSS a partir del valor del deslizador (0-100)."""
        cvss_value = value / 10.0
        self.cvss_label.setText(f"CVSS Mínimo: {cvss_value:.1f}")
        
    def _create_card(self, title_text, value_widget):
        """Función de ayuda para crear una "tarjeta" de resumen."""
        card = QFrame()
        card.setObjectName("SummaryCard")
        card.setMinimumHeight(120)
        
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(15, 15, 15, 15)
        
        title_label = QLabel(title_text)
        title_label.setObjectName("CardTitle")
        
        if isinstance(value_widget, QLabel):
            value_widget.setObjectName("CardValue")
        
        card_layout.addWidget(title_label)
        card_layout.addSpacing(10)
        card_layout.addWidget(value_widget)
        card_layout.addStretch() 
        
        return card

    def _create_main_panel(self):
        """Crea el panel inferior (tabla y detalles)."""
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
        """Pone las cabeceras en su estado inicial (con flecha ▶️)"""
        labels_with_arrow = [f"{text} ▶️" for text in self.original_headers]
        self.hosts_table.setHorizontalHeaderLabels(labels_with_arrow)

    def update_header_labels(self, column_index, order):
        """Actualiza las flechas de las cabeceras según el orden."""
        for i, text in enumerate(self.original_headers):
            item = self.hosts_table.horizontalHeaderItem(i)
            if item is None:
                item = QTableWidgetItem()
                self.hosts_table.setHorizontalHeaderItem(i, item)

            arrow = " ▶️" # Flecha por defecto
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

        try:
            summary_data, hosts_list = parse_nmap_xml(xml_file)
            self.hosts_data = hosts_list 

            self.nmap_command_label.setText(summary_data['nmap_command'])
            self.scanned_assets_label.setText(str(summary_data['scanned_assets']))
            self.services_label.setText(str(summary_data['services']))
            self.ports_label.setText(str(summary_data['ports']))

            # Formateo de OS Families (conteo a la izquierda)
            os_str = "\n".join([f"- {count}: {os}" for os, count in summary_data['os_families'].items()])
            if not os_str: os_str = "-"
            self.os_families_label.setText(os_str)
            
            # Cargar servicios únicos y CVSS
            for host in self.hosts_data:
                for _, service in host['ports']:
                    if service:
                        self.unique_services.add(service)
            
            # Limpiar y rellenar el ComboBox
            self.service_combo.blockSignals(True) # Bloquear señal para evitar filtro prematuro
            self.service_combo.clear()
            self.service_combo.addItem("Mostrar Todos los Servicios")
            sorted_services = sorted(list(self.unique_services))
            self.service_combo.addItems(sorted_services)
            self.service_combo.blockSignals(False)

            # Cargar tarjetas de CVE
            cve_counts = summary_data['cve_counts']
            self.cve_critical_label.setText(f"Critical {cve_counts['Critical']}")
            self.cve_high_label.setText(f"High {cve_counts['High']}")
            self.cve_medium_label.setText(f"Medium {cve_counts['Medium']}")
            self.cve_low_label.setText(f"Low {cve_counts['Low']}")
            
            # Cargar la tabla
            self.load_table_data(self.hosts_data)
            
            self.export_button.setEnabled(True)
            self.details_text.setText("Datos cargados. Usa los filtros para refinar la búsqueda.")

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
        """Rellena la tabla con la lista de datos dada (filtrados o completos)."""
        self.hosts_table.setSortingEnabled(False)
        self.hosts_table.setRowCount(len(data_list))
        
        for i, host_info in enumerate(data_list):
            ip_item = QTableWidgetItem(host_info['ip'])
            
            # Guardamos el índice original en el dato (útil para el filtro)
            ip_item.setData(Qt.UserRole, self.hosts_data.index(host_info)) 
            
            os_item = QTableWidgetItem(host_info['os'])
            
            cvss_item = NumericTableWidgetItem(str(host_info['max_cvss']))
            
            rating, (r, g, b) = get_cvss_rating_and_color(host_info['max_cvss'])
            row_color = QColor(r, g, b, 100) # Fondo con baja opacidad
            
            for item in (ip_item, os_item, cvss_item):
                item.setBackground(row_color)

            self.hosts_table.setItem(i, 0, ip_item)
            self.hosts_table.setItem(i, 1, os_item)
            self.hosts_table.setItem(i, 2, cvss_item)

        self.hosts_table.setSortingEnabled(True)

    def apply_filters(self):
        """Aplica los filtros de CVSS, Servicio y Puertos Comunes a los datos cargados."""
        if not self.hosts_data:
            return

        # 1. Obtener los valores del filtro
        min_cvss = self.cvss_slider.value() / 10.0
        selected_service = self.service_combo.currentText()
        
        # Obtener puertos de botones presionados
        active_ports = []
        active_port_names = []
        for name, btn in self.port_buttons.items():
            if btn.isChecked():
                active_ports.extend(self.common_ports[name])
                active_port_names.append(name)
        
        # 2. Inicializar la lista de hosts filtrados
        filtered_hosts = []

        # 3. Recorrer la lista de hosts para aplicar la lógica
        for host in self.hosts_data:
            cvss_pass = True
            service_pass = True
            port_pass = True 

            # --- Lógica de Filtro CVSS ---
            if float(host['max_cvss']) < min_cvss:
                cvss_pass = False

            # --- Lógica de Filtro de Servicio (por nombre) ---
            if selected_service != "Mostrar Todos los Servicios":
                service_pass = False 
                for _, service in host['ports']:
                    if service == selected_service:
                        service_pass = True
                        break

            # --- Lógica de Filtro de Puertos Comunes (por número) ---
            if active_ports: 
                port_pass = False 
                
                # CORRECCIÓN IMPORTANTE: Convertimos los puertos del host a enteros 
                # para que coincida con los enteros de active_ports (ej. 22, 445).
                try:
                    host_ports = [int(p) for p, s in host['ports']] 
                except ValueError:
                    # En un escenario real, esto no debería pasar si p es portid
                    host_ports = [] 
                
                for required_port in active_ports:
                    if required_port in host_ports: 
                        port_pass = True
                        break 

            # 4. Si el host pasa TODOS los filtros (AND), lo añadimos a la lista
            if cvss_pass and service_pass and port_pass: 
                filtered_hosts.append(host)

        # 5. Cargar los datos filtrados en la tabla y actualizar detalles
        self.load_table_data(filtered_hosts)
        
        details_text = f"Filtrado aplicado:\n"
        details_text += f"- CVSS Mínimo: {min_cvss:.1f}\n"
        details_text += f"- Servicio por Nombre: {selected_service}\n"
        details_text += f"- Puertos Comunes Activos: {', '.join(active_port_names) if active_port_names else 'Ninguno'}\n"
        details_text += f"\nMostrando {len(filtered_hosts)} de {len(self.hosts_data)} hosts."
        self.details_text.setText(details_text)


    def show_host_details(self, row, column):
        ip_item = self.hosts_table.item(row, 0)
        if ip_item is None:
            return
        
        try:
            # Usamos el dato guardado para obtener el índice original, incluso si la tabla está filtrada
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
            for port, service in host_info['ports']:
                details_str += f"   - Puerto: {port:<5} Servicio: {service}\n"
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
        # ... (función de exportación sin cambios) ...
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


# --- El código para arrancar la aplicación ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DashboardApp()
    window.show()
    sys.exit(app.exec())