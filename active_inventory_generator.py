import xml.etree.ElementTree as ET

def get_cvss_rating_and_color(score_str):
    """
    Convierte una puntuación CVSS en un Nivel y un Color.
    Paleta: Rojo, Naranja, Violeta, Gris
    """
    try:
        score = float(score_str)
        if 9.0 <= score <= 10.0:
            return "Critical", (217, 83, 79)  # Rojo
        elif 7.0 <= score <= 8.9:
            return "High", (240, 173, 78)      # Naranja
        elif 4.0 <= score <= 6.9:
            return "Medium", (182, 109, 255)  # Violeta
        elif 0.1 <= score <= 3.9:
            return "Low", (119, 119, 119)      # Gris
        else: # Puntuación 0.0
             return "None", (200, 200, 200)
    except (ValueError, TypeError):
        return "Unknown", (150, 150, 150) # Gris para Desconocido

def get_info_vuln(node, port="unknown", service="unknown"):
    """
    Extrae la información de una vulnerabilidad desde un nodo <script>.
    """
    vuln_cve = []
    vulnerabilities = []

    elem = node.find("table") 
    if elem is None:
        return [] 

    # --- Extraer CVEs ---
    cves_table = elem.find(".//table[@key='ids']")
    if cves_table is not None:
        for cve in cves_table.findall('elem'):
            vuln_cve.append(cve.text.split(':')[-1])

    # --- Extraer CVSS ---
    cvss_node = elem.find(".//elem[@key='cvss']")
    cvss_score = cvss_node.text if cvss_node is not None else 'N/A'

    # --- Extraer otros datos ---
    title_node = elem.find(".//elem[@key='title']")
    state_node = elem.find(".//elem[@key='state']")
    
    # --- INICIO: NUEVOS CAMPOS PARA EXCEL ---
    desc_node = elem.find(".//table[@key='description']/elem")
    description = desc_node.text if desc_node is not None else "N/A"
    
    disc_date_node = elem.find(".//elem[@key='disclosure']")
    disclosure_date = disc_date_node.text if disc_date_node is not None else 'unknown'
    
    references = []
    refs_table = elem.find(".//table[@key='refs']")
    if refs_table is not None:
        references = [e.text for e in refs_table.findall('elem') if e.text]
    # --- FIN: NUEVOS CAMPOS PARA EXCEL ---
    
    if title_node is None or state_node is None:
        return [] 
    
    vulnerabilities.append({
        'port': port,
        'service': service,
        'name': title_node.text,
        'state': state_node.text,
        'cve': vuln_cve,
        'cvss': cvss_score,
        'description': description,
        'disclosure_date': disclosure_date,
        'references': references
    })

    return vulnerabilities

def extract_host_info(host):
    """
    Extrae IP, Puertos, Vulnerabilidades y SO de un nodo <host>.
    """
    ip = host.find('address').attrib['addr']
    ports = []
    vulnerabilities = []

    # --- Extraer Puertos y Vulnerabilidades por puerto ---
    for port in host.find('ports').findall('port'):
        if "open" == port.find('state').attrib.get('state'):          
            
            # --- ¡AQUÍ ESTÁ LA CORRECCIÓN! ---
            # Cambiado de 'portId' a 'portid' (todo minúsculas)
            port_id = port.attrib['portid']
            # --- FIN DE LA CORRECCIÓN ---

            service_node = port.find('service')
            service = service_node.attrib.get('name', 'unknown') if service_node is not None else 'unknown'
            ports.append((port_id, service))

            for script in port.findall('script'):
                if 'vulnerable' in script.attrib['output'].lower() or 'vulners' in script.attrib['id']:
                    vulnerabilities.extend(get_info_vuln(script, port_id, service))
                    
    # --- Extraer SO ---
    os_match = host.find(".//osmatch")
    
    # Usamos el nombre completo del SO, tal como lo detecta Nmap.
    os_name = os_match.attrib.get('name', 'Desconocido') if os_match is not None else 'Desconocido'

    return ip, os_name, ports, vulnerabilities

def parse_nmap_xml(xml_file):
    """
    Función principal que analiza todo el XML y devuelve datos estructurados.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # --- Extraer comando Nmap ---
    nmap_command = root.attrib.get('args', 'Comando no encontrado')

    # --- Contadores para el dashboard ---
    hosts_data = [] # Para la tabla
    os_families = {}
    
    # --- ¡CAMBIO AQUÍ! ---
    # Ya no usamos 'set()', usamos contadores numéricos
    total_open_ports = 0
    total_running_services = 0
    # --- FIN DEL CAMBIO ---
    
    cve_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0, "Unknown": 0}

    # --- Procesar cada host ---
    for host in root.findall('host'):
        ip, os_name, ports, vulnerabilities = extract_host_info(host)
        
        # Actualizar contadores
        os_families[os_name] = os_families.get(os_name, 0) + 1
        
        # --- ¡CAMBIO AQUÍ! ---
        # Sumamos la cantidad de puertos/servicios de ESTE host al total
        # 'ports' es una lista, así que len(ports) es el número de puertos abiertos
        total_open_ports += len(ports)
        total_running_services += len(ports) # Es el mismo número
        # --- FIN DEL CAMBIO ---

        max_cvss_score = 0.0
        for vuln in vulnerabilities:
            # Contar CVEs por criticidad
            rating, color = get_cvss_rating_and_color(vuln['cvss'])
            cve_counts[rating] += 1
            
            # Encontrar la criticidad máxima para este host
            try:
                max_cvss_score = max(max_cvss_score, float(vuln['cvss']))
            except (ValueError, TypeError):
                continue
        
        # Ya no necesitamos este bucle, porque sumamos los puertos arriba
        # for port, service in ports:
        #    all_ports.add(port)
        #    all_services.add(service)

        hosts_data.append({
            'ip': ip,
            'os': os_name,
            'ports': ports,
            'vulnerabilities': vulnerabilities,
            'max_cvss': max_cvss_score
        })

    # --- Empaquetar resultados del dashboard ---
    summary_data = {
        "nmap_command": nmap_command,
        "scanned_assets": len(hosts_data),
        "os_families": os_families,
        
        # --- ¡CAMBIO AQUÍ! ---
        "services": total_running_services,
        "ports": total_open_ports,
        # --- FIN DEL CAMBIO ---
        
        "cve_counts": cve_counts
    }

    return summary_data, hosts_data