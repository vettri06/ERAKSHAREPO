import logging
import subprocess
import shutil
import xml.etree.ElementTree as ET
from typing import Dict
import time
import os
import json
import re
import socket

logger = logging.getLogger(__name__)
scanlog = logging.getLogger("iot_scanner")

class NmapScanner:
    def __init__(self):
        self.naabu_path = shutil.which("naabu")
        self.zgrab2_path = shutil.which("zgrab2")
        self.nmap_path = shutil.which("nmap")
        if not self.naabu_path:
            gopath = os.environ.get("GOPATH", os.path.expanduser(r"~\go"))
            candidate = os.path.join(gopath, "bin", "naabu.exe")
            if os.path.exists(candidate):
                self.naabu_path = candidate
        if not self.zgrab2_path:
            gopath = os.environ.get("GOPATH", os.path.expanduser(r"~\go"))
            candidate = os.path.join(gopath, "bin", "zgrab2.exe")
            if os.path.exists(candidate):
                self.zgrab2_path = candidate
        if not (self.naabu_path or self.nmap_path):
            logger.warning("No external scanner found (naabu/nmap). Will fallback to Python socket scan.")
        if self.naabu_path:
            scanlog.info(f"Using Naabu for port discovery: {self.naabu_path}")
        elif self.nmap_path:
            scanlog.info(f"Using Nmap fallback for port discovery: {self.nmap_path}")
        else:
            scanlog.info("Using Python socket fallback for port discovery")

    def scan_device(self, ip: str, quick_scan: bool = True, stop_callback=None) -> Dict:
        start_time = time.time()
        if self.naabu_path:
            scanlog.info(f"Starting open-port discovery on {ip}")
            return self._scan_with_naabu(ip, quick_scan, stop_callback, start_time)
        if self.nmap_path:
            scanlog.info(f"Starting Nmap open-port discovery on {ip}")
            return self._scan_with_nmap(ip, quick_scan, stop_callback, start_time)
        scanlog.info(f"Starting socket-based open-port discovery on {ip}")
        return self._scan_with_socket(ip, quick_scan, stop_callback, start_time)

    def _scan_with_naabu(self, ip: str, quick_scan: bool, stop_callback, start_time: float) -> Dict:
        ports = []
        services = {}
        try:
            naabu_cmd = [self.naabu_path, "-host", ip, "-json", "-scan-type", "connect"]
            if quick_scan:
                naabu_cmd.extend(["-top-ports", "100"])
            else:
                naabu_cmd.extend(["-top-ports", "1000"])
            proc = subprocess.Popen(naabu_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL)
            while True:
                if stop_callback and stop_callback():
                    proc.terminate()
                    return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}, 'scan_duration': time.time() - start_time}
                if proc.poll() is not None:
                    break
                time.sleep(0.2)
            stdout, _ = proc.communicate()
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get("host") == ip and obj.get("port"):
                    ports.append({"port": int(obj["port"]), "protocol": obj.get("protocol", "tcp"), "service": "unknown", "product": "", "version": "", "full_version": "", "state": "open"})
            scanlog.info(f"Open ports found on {ip}: {len(ports)}")
            for p in ports:
                info = self._probe_service_with_zgrab(ip, p["port"])
                if info:
                    p.update(info)
                    services[p["service"]] = p
            if services:
                scanlog.info(f"Services identified on {ip}: {len(services)}")
            result = {"ip": ip, "ports": ports, "services": services, "os_info": {}}
            result["scan_duration"] = time.time() - start_time
            return result
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}, 'scan_duration': time.time() - start_time}

    def _scan_with_nmap(self, ip: str, quick_scan: bool, stop_callback, start_time: float) -> Dict:
        open_cmd = [self.nmap_path, "-Pn", "--reason", "-T5"]
        if quick_scan:
            open_cmd.extend(["--top-ports", "100"])
        else:
            open_cmd.extend(["--top-ports", "300"])
        open_cmd.extend(["-oX", "-", ip])
        try:
            # Use stdin=subprocess.DEVNULL
            p1 = subprocess.Popen(open_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL)
            while True:
                if stop_callback and stop_callback():
                    p1.terminate()
                    return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}, 'scan_duration': time.time() - start_time}
                
                try:
                    # Try to communicate with timeout to check for completion
                    # This reads stdout/stderr so buffer doesn't fill up
                    xml1, err1 = p1.communicate(timeout=0.5)
                    break # Process finished
                except subprocess.TimeoutExpired:
                    # Process still running, loop again to check callback
                    continue
                except Exception as e:
                    logger.error(f"Error during Nmap execution: {e}")
                    p1.kill()
                    return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}, 'scan_duration': time.time() - start_time}

            if p1.returncode != 0 and not xml1:
                return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}, 'scan_duration': time.time() - start_time}
            parsed1 = self._parse_nmap_xml(xml1, ip)
            ports_list = parsed1.get("ports", [])
            scanlog.info(f"Open ports found on {ip}: {len(ports_list)}")
            if not ports_list:
                return {"ip": ip, "ports": [], "services": {}, "os_info": {}, "scan_duration": time.time() - start_time}
            port_str = ",".join(str(p["port"]) for p in ports_list)
            svc_cmd = [self.nmap_path, "-sV", "-Pn", "--version-all", "-T4", "-p", port_str, "-oX", "-", ip]
            
            # Use stdin=subprocess.DEVNULL
            p2 = subprocess.Popen(svc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, stdin=subprocess.DEVNULL)
            xml2 = ""
            while True:
                if stop_callback and stop_callback():
                    p2.terminate()
                    break
                
                try:
                    xml2, err2 = p2.communicate(timeout=0.5)
                    break
                except subprocess.TimeoutExpired:
                    continue
                except Exception as e:
                    logger.error(f"Error during Nmap service scan: {e}")
                    p2.kill()
                    break
            services = {}
            if xml2:
                parsed2 = self._parse_nmap_xml(xml2, ip)
                svc_ports = parsed2.get("ports", [])
                by_port = {p["port"]: p for p in svc_ports}
                for p in ports_list:
                    enrich = by_port.get(p["port"])
                    if enrich:
                        p.update({
                            "service": enrich.get("service", p.get("service", "unknown")),
                            "product": enrich.get("product", ""),
                            "version": enrich.get("version", ""),
                            "full_version": enrich.get("full_version", "").strip() or (enrich.get("product","") + (" " + enrich.get("version","") if enrich.get("version") else "")).strip()
                        })
                        services[p["service"]] = p
            if services:
                scanlog.info(f"Services identified on {ip}: {len(services)}")
            result = {"ip": ip, "ports": ports_list, "services": services, "os_info": {}}
            result["scan_duration"] = time.time() - start_time
            return result
        except Exception:
            return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}, 'scan_duration': time.time() - start_time}

    def _scan_with_socket(self, ip: str, quick_scan: bool, stop_callback, start_time: float) -> Dict:
        common_ports = [22, 23, 21, 25, 80, 110, 143, 443, 445, 135, 3306, 5432, 6379, 27017, 3389, 8000, 8080]
        if not quick_scan:
            common_ports += [53, 139, 389, 1900, 5353]
        ports = []
        services = {}
        for port in common_ports:
            if stop_callback and stop_callback():
                break
            try:
                with socket.create_connection((ip, port), timeout=0.8) as s:
                    s.settimeout(0.8)
                    banner = ""
                    try:
                        if port in (80, 8080, 8000, 443):
                            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = s.recv(256).decode(errors="ignore")
                    except Exception:
                        pass
                    service = "unknown"
                    product = ""
                    version = ""
                    if banner:
                        m = re.search(r"([A-Za-z][A-Za-z0-9_\\-]*)\\s*([\\d\\.]+)?", banner)
                        if m:
                            product = m.group(1)
                            version = m.group(2) or ""
                    full_version = (product + (" " + version if version else "")).strip()
                    entry = {"port": port, "protocol": "tcp", "service": service, "product": product, "version": version, "full_version": full_version, "state": "open"}
                    ports.append(entry)
                    if service:
                        services[service] = entry
            except Exception:
                continue
        return {"ip": ip, "ports": ports, "services": services, "os_info": {}, "scan_duration": time.time() - start_time}
    def scan_udp_ports(self, ip: str) -> Dict:
        return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}}

    def check_http_headers(self, ip: str) -> Dict:
        return {}

    def enhanced_device_scan(self, ip: str) -> Dict:
        return {}

    def _parse_nmap_xml(self, xml_content: str, ip: str) -> Dict:
        try:
            root = ET.fromstring(xml_content)
            
            ports_list = []
            services_dict = {}
            os_info = {}
            
            # Ports and Services
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                
                port_id = int(port.get("portid"))
                protocol = port.get("protocol")
                
                service = port.find("service")
                service_name = "unknown"
                product = ""
                version = ""
                
                if service is not None:
                    service_name = service.get("name", "unknown")
                    product = service.get("product", "")
                    version = service.get("version", "")
                
                # Construct full version string
                full_version = product
                if version:
                    full_version += f" {version}"
                full_version = full_version.strip()
                
                port_data = {
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "full_version": full_version,
                    "state": "open"
                }
                
                ports_list.append(port_data)
                services_dict[service_name] = port_data

            # OS Detection
            os_match = root.find(".//osmatch")
            if os_match is not None:
                os_info = {
                    "name": os_match.get("name"),
                    "accuracy": os_match.get("accuracy"),
                    "osclass": []
                }
                for osclass in os_match.findall("osclass"):
                    os_info["osclass"].append({
                        "type": osclass.get("type"),
                        "vendor": osclass.get("vendor"),
                        "osfamily": osclass.get("osfamily"),
                        "osgen": osclass.get("osgen")
                    })

            return {
                "ip": ip,
                "ports": ports_list,
                "services": services_dict,
                "os_info": os_info
            }

        except ET.ParseError:
            logger.error(f"Failed to parse XML for {ip}")
            return {'ip': ip, 'ports': [], 'services': {}, 'os_info': {}}

    def _probe_service_with_zgrab(self, ip: str, port: int) -> Dict:
        if not self.zgrab2_path:
            return {}
        module, args = self._select_zgrab_module(port)
        cmd = [self.zgrab2_path, module] + args + ["--port", str(port), "--output-file", "-"]
        try:
            res = subprocess.run(cmd, input=ip + "\n", capture_output=True, text=True, timeout=15)
            if res.returncode != 0 or not res.stdout:
                return {}
            data = None
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if obj.get("status") == "success":
                    data = obj.get("data", {})
                    break
            if not data:
                return {}
            return self._extract_service_info(module, data, port)
        except Exception:
            return {}

    def _select_zgrab_module(self, port: int):
        http_ports = {80, 8080, 8000, 8888}
        https_ports = {443, 8443}
        mapping = {
            22: ("ssh", []),
            21: ("ftp", []),
            25: ("smtp", []),
            110: ("pop3", []),
            995: ("pop3", ["--starttls"]),
            143: ("imap", []),
            993: ("imap", ["--starttls"]),
            3306: ("mysql", []),
            5432: ("postgres", []),
            6379: ("redis", []),
            27017: ("mongodb", []),
            3389: ("rdp", []),
            23: ("telnet", []),
            1883: ("banner", []),
            8883: ("banner", []),
            5683: ("banner", [])
        }
        if port in http_ports:
            return ("http", ["--max-redirects", "0"])
        if port in https_ports:
            return ("http", ["--use-https", "--max-redirects", "0"])
        return mapping.get(port, ("banner", []))

    def _extract_service_info(self, module: str, data: Dict, port: int) -> Dict:
        service = module if module != "banner" else "unknown"
        product = ""
        version = ""
        if module == "http":
            http = data.get("http", {})
            resp = http.get("result", {}).get("response", {})
            headers = resp.get("headers", {})
            server = headers.get("Server") or headers.get("server")
            if server:
                product = server
                m = re.search(r"([\\w\\-]+)\\/?\\s*([\\d\\.]+)", server)
                if m:
                    product = m.group(1)
                    version = m.group(2)
            service = "http" if port not in {443, 8443} else "https"
        elif module == "ssh":
            ssh = data.get("ssh", {})
            banner = ssh.get("server_id") or ssh.get("banner")
            if banner:
                product = banner
                m = re.search(r"OpenSSH[_\\s-]*([\\d\\.]+)", banner, re.I)
                if m:
                    product = "OpenSSH"
                    version = m.group(1)
            service = "ssh"
        elif module in {"ftp", "smtp", "pop3", "imap", "redis", "mongodb", "mysql", "postgres", "telnet", "rdp"}:
            obj = data.get(module, {})
            banner = obj.get("banner") or obj.get("result", {}).get("banner")
            if banner:
                product = banner
                m = re.search(r"([A-Za-z][A-Za-z0-9_\\-]*)\\s*([\\d\\.]+)", banner)
                if m:
                    product = m.group(1)
                    version = m.group(2)
            service = module
        else:
            ban = data.get("banner", {})
            b = ban.get("banner")
            if b:
                product = b
                m = re.search(r"([A-Za-z][A-Za-z0-9_\\-]*)\\s*([\\d\\.]+)", b)
                if m:
                    product = m.group(1)
                    version = m.group(2)
        full_version = (product + (" " + version if version else "")).strip()
        return {"service": service, "product": product, "version": version, "full_version": full_version}
