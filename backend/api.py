from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi import Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import threading
import time
from datetime import datetime
import logging
import sys
import os
import json
import hashlib
import shutil
import tempfile
from fastapi.responses import FileResponse
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request

# Configure logging first, before importing other modules if possible,
# or ensure basicConfig is called early.
# Remove the custom api_logger setup and use the root logger configuration.
# This ensures all modules (iot_security.*) that use logging.getLogger(__name__)
# will inherit this configuration.

logging.basicConfig(
    level=logging.DEBUG,  # Capture DEBUG logs from everything
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Create a logger for the API module specifically
api_logger = logging.getLogger("api")

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from iot_scanner import IoTSecurityScanner
from config import MAC_OUI_MAPPING
import requests

app = FastAPI(title="IoT Security Scanner API")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Skip logging for debug log download to avoid file locking issues
    if "/api/debug/log" in str(request.url):
        return await call_next(request)

    body = await request.body()
    api_logger.info(f"Request: {request.method} {request.url}")
    if body:
        try:
            api_logger.debug(f"Request Body: {body.decode()}")
        except:
            api_logger.debug(f"Request Body: <binary or non-utf8>")
    
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    
    api_logger.info(f"Response Status: {response.status_code} (took {duration:.3f}s)")
    return response

scanner = IoTSecurityScanner()
# try:
#     scanner.load_last_scan()
# except Exception as e:
#     print(f"Failed to load last scan: {e}")
activity_log = []
system_logs = []
def add_activity(type: str, message: str, severity: str = "info"):
    activity_log.insert(0, {
        "id": f"act-{int(time.time()*1000)}",
        "type": type,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "severity": severity
    })
    if len(activity_log) > 50:
        activity_log.pop()
def add_log(level: str, message: str, source: str = "system"):
    system_logs.insert(0, {
        "id": f"log-{int(time.time()*1000)}",
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message,
        "source": source
    })
    if len(system_logs) > 100:
        system_logs.pop()
class MemoryLogHandler(logging.Handler):
    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname.lower()
            if level == 'warning':
                level = 'warning'
            elif level == 'error' or level == 'critical':
                level = 'error'
            else:
                level = 'info'
            add_log(level, msg, source="scanner")
            if "[+]" in msg or "Scanning device" in msg:
                clean_msg = msg.replace("[+]", "").strip()
                add_activity("scan_progress", clean_msg, "info")
            elif "Discovery complete" in msg:
                 add_activity("discovery", msg, "success")
            elif "Vulnerability found" in msg or "vulnerabilities" in msg.lower():
                 if "Found" in msg and "vulnerabilities" in msg:
                     add_activity("vuln_found", msg, "warning")
            elif "Report generated" in msg:
                 add_activity("report", "New scan report generated", "success")
        except Exception:
            self.handleError(record)
scanner_logger = logging.getLogger("iot_scanner")
memory_handler = MemoryLogHandler()
memory_handler.setFormatter(logging.Formatter('%(message)s'))
scanner_logger.addHandler(memory_handler)
scanner_logger.setLevel(logging.INFO)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
class ScanConfig(BaseModel):
    interface: str
    mode: str | int = 1
class LoginCredentials(BaseModel):
    username: str
    password: str
class DeviceConfigUpdate(BaseModel):
    vendor: Optional[str] = None
    type: Optional[str] = None
@app.get("/api/interfaces")
def get_interfaces():
    try:
        interfaces = scanner.get_available_interfaces()
        return {
            "success": True,
            "data": [
                {
                    "name": iface,
                    "displayName": iface,
                    "ip": ip,
                    "netmask": "255.255.255.0",  
                    "mac": mac,
                    "type": "ethernet" if "eth" in iface.lower() else "wifi" if "wlan" in iface.lower() or "wi-fi" in iface.lower() else "virtual" if "vmware" in iface.lower() or "virtual" in iface.lower() else "other",
                    "status": status.lower(),
                    "isDefault": False
                }
                for iface, ip, status, mac in interfaces
            ]
        }
    except Exception as e:
        add_log("error", f"Failed to get interfaces: {e}")
        return {"success": False, "error": str(e)}
def run_scan_background(interface: str, mode: str | int, extra_subnets: Optional[List[str]] = None):
    try:
        # Reset state before starting new scan
        scanner.reset_state()
        
        add_activity("scan_started", f"Started scan on {interface}", "info")
        add_log("info", f"Scan started on {interface} with mode {mode}")
        scan_mode = 1
        if isinstance(mode, str):
            if mode.lower() == 'deep':
                scan_mode = 2
            elif mode.lower() == 'comprehensive':
                scan_mode = 3
        elif isinstance(mode, int):
            scan_mode = mode
        scanner.run_scan(scan_mode=scan_mode, interface_choice=interface, extra_subnets=extra_subnets)
        add_activity("scan_completed", f"Scan completed on {interface}", "success")
        add_log("info", f"Scan completed on {interface}")
    except Exception as e:
        api_logger.error(f"Scan failed: {e}")
        add_activity("alert", f"Scan failed: {e}", "critical")
        add_log("error", f"Scan failed: {e}")
@app.post("/api/scan/start")
def start_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    if scanner.is_scanning:
        return {"success": False, "error": "Scan already in progress"}
    try:
        mode_str = str(config.mode).lower() if isinstance(config.mode, str) else config.mode
        if mode_str == "deep" or mode_str == 2:
            scanner.scan_mode_name = "deep"
        elif mode_str == "comprehensive" or mode_str == 3:
            scanner.scan_mode_name = "comprehensive"
        else:
            scanner.scan_mode_name = "quick"
    except Exception:
        scanner.scan_mode_name = "quick"
    # Be defensive in case running server hasn't reloaded model yet
    extra_subnets = getattr(config, 'extra_subnets', None)
    background_tasks.add_task(run_scan_background, config.interface, config.mode, extra_subnets)
    return {
        "success": True, 
        "data": {
            "id": f"scan-{int(time.time())}",
            "status": "running",
            "startTime": datetime.now().isoformat(),
            "mode": config.mode,
            "interface": config.interface
        }
    }
@app.post("/api/scan/stop")
def stop_scan():
    if scanner.is_scanning:
        scanner.stop_scan()
        add_activity("alert", "Scan stopped by user", "warning")
        add_log("warning", "Scan stopped by user")
        return {"success": True, "message": "Stopping scan..."}
    return {"success": False, "error": "No scan running"}
@app.get("/api/scan/status")
def get_scan_status():
    status = "running" if scanner.is_scanning else "idle"
    if scanner.should_stop and scanner.is_scanning:
        status = "running" 
    devices_scanned = len(scanner.results)
    vulns_found = sum(len(d.get("vulnerabilities", [])) for d in scanner.results.values())
    progress = scanner.scan_progress if status == "running" else 100 if status == "idle" and devices_scanned > 0 else 0
    total_devices = devices_scanned
    return {
        "success": True,
        "data": {
            "id": f"scan-{int(time.time())}",
            "status": status,
            "mode": getattr(scanner, "scan_mode_name", "quick"), 
            "interface": scanner.selected_interface or "Unknown",
            "progress": progress,
            "devicesScanned": devices_scanned,
            "totalDevices": total_devices, 
            "vulnerabilitiesFound": vulns_found,
            "currentDevice": f"Scanning {scanner.current_scan_device}" if getattr(scanner, 'current_scan_device', None) else "Scanning..." if status == "running" else None,
            "startTime": datetime.now().isoformat()
        }
    }
def format_vulnerability(v, device_ip):
    severity_map = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info"
    }
    sev_upper = v.get("severity", "LOW").upper()
    severity = severity_map.get(sev_upper, "low")
    cvss_map = {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.0,
        "info": 0.0
    }
    unique_str = f"{v.get('id')}{v.get('description')}{device_ip}"
    vuln_id = hashlib.md5(unique_str.encode()).hexdigest()[:12]
    return {
        "id": vuln_id,
        "cve_id": v.get("id", "N/A"),
        "severity": severity,
        "cvss_score": v.get("cvss_score", cvss_map.get(severity, 0.0)),
        "description": v.get("description", "No description available"),
        "remediation": v.get("remediation", v.get("solution", "No specific remediation provided. Please update the software to the latest version.")),
        "download_link": v.get("download_link"),
        "affected_devices": [device_ip],
        "references": v.get("references", []),
        "published_date": datetime.now().isoformat(),
        "last_modified": datetime.now().isoformat(),
        "version_checked": v.get("version_checked") or v.get("version")
    }
@app.get("/api/devices")
def get_devices():
    try:
        devices = []
        api_logger.info(f"DEBUG: get_devices called. Scanner has {len(scanner.results)} results.")
        for ip, info in scanner.results.items():
            vulns_raw = info.get("vulnerabilities", [])
            api_logger.info(f"DEBUG: Device {ip} has {len(vulns_raw)} raw vulnerabilities.")
            try:
                vulns = [format_vulnerability(v, ip) for v in vulns_raw]
                api_logger.info(f"DEBUG: Device {ip} has {len(vulns)} formatted vulnerabilities.")
            except Exception as ve:
                api_logger.error(f"Error formatting vulnerabilities for {ip}: {ve}")
                vulns = []
            risk_level = "low"
            if any(v.get('severity') == 'critical' for v in vulns):
                risk_level = "critical"
            elif any(v.get('severity') == 'high' for v in vulns):
                risk_level = "high"
            elif any(v.get('severity') == 'medium' for v in vulns):
                risk_level = "medium"
            raw_type = info.get("device_type", "unknown").lower()
            
            # Map ML/Fallback specific types to Frontend generic types
            type_mapping = {
                'linux_device': 'computer',
                'windows_device': 'computer',
                'raspberry_pi': 'computer',
                'esp_device': 'sensor',
                'iot_device': 'sensor',
                'web_server': 'computer',
                'ssh_server': 'computer',
                'metasploitable': 'computer',
                'generic_device': 'unknown'
            }
            if raw_type in type_mapping:
                raw_type = type_mapping[raw_type]

            valid_types = ['router', 'switch', 'camera', 'sensor', 'thermostat', 'smart_speaker', 'smart_tv', 'computer', 'phone', 'printer', 'nas', 'unknown', 'cant_determine']
            if raw_type == 'cant determine': raw_type = 'cant_determine'
            device_type = raw_type if raw_type in valid_types else 'unknown'
            
            # Resolve vendor from OUI if unknown
            vendor = info.get("vendor", "Unknown")
            mac = info.get("mac", "Unknown")
            if (not vendor or vendor.lower() == "unknown") and mac and mac.lower() != "unknown":
                vendor = resolve_vendor_from_oui(mac)
                if vendor != "Unknown":
                    # Update scanner result cache
                    scanner.results[ip]["vendor"] = vendor

            raw_ports = info.get("ports", [])
            processed_ports = []
            services_list = []
            for p in raw_ports:
                if isinstance(p, dict):
                    port_num = int(p.get('port', 0))
                    service = p.get('service', 'unknown')
                    processed_ports.append({
                        "number": port_num,
                        "protocol": "tcp",
                        "service": service,
                        "state": "open",
                        "product": p.get("product") or "",
                        "version": p.get("version") or ""
                    })
                    services_list.append(service)
                elif isinstance(p, (int, str)):
                    try:
                        port_num = int(p)
                        processed_ports.append({"number": port_num, "protocol": "tcp", "service": "unknown", "state": "open"})
                        services_list.append(str(port_num))
                    except:
                        pass
            devices.append({
                "id": info.get("mac", ip),
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": info.get("hostname", ip),
                "type": device_type,
                "riskLevel": risk_level,
                "status": "online",
                "lastSeen": info.get("last_seen", datetime.now().isoformat()),
                "firstSeen": info.get("first_seen", datetime.now().isoformat()),
                "os": info.get("os_match", "Unknown"),
                "services": services_list,
                "ports": processed_ports,
                "vulnerabilities": vulns
            })
        return {"success": True, "data": devices}
    except Exception as e:
        api_logger.error(f"Error in get_devices: {e}")
        import traceback
        api_logger.error(traceback.format_exc())
        return {"success": False, "error": str(e)}
@app.put("/api/devices/{device_id}/config")
def update_device_config(device_id: str, update: DeviceConfigUpdate):
    try:
        target_ip = None
        target_info = None
        for ip, info in scanner.results.items():
            if info.get("mac") == device_id or ip == device_id:
                target_ip = ip
                target_info = info
                break
        if not target_ip or not target_info:
            return {"success": False, "error": "Device not found"}
        valid_types = ['router', 'switch', 'camera', 'sensor', 'thermostat', 'smart_speaker', 'smart_tv', 'computer', 'phone', 'printer', 'nas', 'unknown']
        if update.type:
            t = update.type.lower()
            target_info["device_type"] = t if t in valid_types else "unknown"
        if update.vendor:
            target_info["vendor"] = update.vendor
        nmap_results = {
            "ports": target_info.get("ports", []),
            "services": target_info.get("services", {}),
            "os_info": target_info.get("os_info", {}),
        }
        try:
            vulnerabilities = scanner.vuln_checker.check_device_vulnerabilities(target_info, nmap_results)
            if vulnerabilities:
                target_info["vulnerabilities"] = vulnerabilities
        except Exception as ve:
            api_logger.error(f"Error rechecking vulnerabilities for {target_ip}: {ve}")
        scanner.results[target_ip] = target_info
        try:
            overrides_path = scanner.discovery.output_file if hasattr(scanner, "discovery") else os.path.join(os.path.dirname(__file__), "devices.json")
            try:
                with open(overrides_path, 'r') as f:
                    existing_devices = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                existing_devices = {}
            entry = existing_devices.get(target_ip) or {}
            entry.setdefault("ip", target_ip)
            entry.setdefault("mac", target_info.get("mac", "Unknown"))
            if update.vendor:
                entry["vendor_manual"] = update.vendor
            if update.type:
                entry["device_type_manual"] = target_info.get("device_type", "unknown")
            existing_devices[target_ip] = entry
            try:
                scanner.discovery.discovered_devices = existing_devices
                scanner.discovery.save_devices(existing_devices)
            except Exception:
                with open(overrides_path, 'w') as f:
                    json.dump(existing_devices, f, indent=2)
        except Exception as pe:
            api_logger.error(f"Error persisting overrides: {pe}")
        add_activity("device_updated", f"Updated config for {target_ip}", "info")
        return {"success": True, "data": {"ip": target_ip}}
    except Exception as e:
        api_logger.error(f"Error in update_device_config: {e}")
        return {"success": False, "error": str(e)}
# Global OUI Cache
OUI_CACHE_FILE = os.path.join(os.path.dirname(__file__), "ieee_vendors.json")
OUI_MAPPING_CACHE = {}  # In-memory cache

def load_oui_cache():
    global OUI_MAPPING_CACHE
    try:
        if os.path.exists(OUI_CACHE_FILE):
            with open(OUI_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                OUI_MAPPING_CACHE = data.get("oui_map", {})
    except Exception as e:
        api_logger.error(f"Failed to load OUI cache: {e}")

def resolve_vendor_from_oui(mac: str) -> str:
    """Resolve vendor name from MAC address using OUI cache."""
    if not mac or mac.lower() == "unknown":
        return "Unknown"
    
    clean_mac = mac.replace(":", "").replace("-", "").upper()
    if len(clean_mac) >= 6:
        oui = clean_mac[:6]
        if oui in OUI_MAPPING_CACHE:
            return OUI_MAPPING_CACHE[oui]
            
        # Try checking against local variable if cache not yet loaded? 
        # (OUI_MAPPING_CACHE is global and updated in place)
    return "Unknown"

def load_vendors_from_local_file():
    """Load vendors from local vendors.txt file"""
    add_log("info", "Loading vendors from local vendors.txt...", "system")
    try:
        vendors_txt_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vendors.txt")
        if not os.path.exists(vendors_txt_path):
             api_logger.warning(f"vendors.txt not found at {vendors_txt_path}")
             return

        vendors_set = set()
        oui_map = {}
        
        try:
            with open(vendors_txt_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                
            for line in lines:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    if len(parts) >= 2:
                        assignment = parts[0].strip()
                        name = parts[1].strip()
                        if name and name.lower() not in ["private", "unknown"]:
                            vendors_set.add(name)
                            oui = assignment.upper().replace(":", "").replace("-", "")
                            if len(oui) >= 6:
                                oui_map[oui[:6]] = name
        except Exception as e:
            api_logger.error(f"Error parsing vendors.txt: {e}")

        # Add curated list (keep these as they are important)
        curated = [
            "Cisco","Juniper","TP-Link","D-Link","Netgear","Ubiquiti","Huawei","ZTE","Hikvision","Dahua","Aruba",
            "Dell","HP","Synology","QNAP","MikroTik","Palo Alto","Fortinet","VMware","Apple","Raspberry Pi","Espressif","ASUS","Belkin","Samsung"
        ]
        for v in curated:
            vendors_set.add(v)
            
        # Add existing static mapping
        for mac_prefix, vendor in MAC_OUI_MAPPING.items():
            vendors_set.add(vendor)
            oui = mac_prefix.upper().replace(":", "").replace("-", "")
            if len(oui) >= 6:
                oui_map[oui[:6]] = vendor

        vendor_list = sorted(vendors_set)
        
        # Save to file (cache)
        with open(OUI_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "vendors": vendor_list, 
                "oui_map": oui_map,
                "updated": datetime.now().isoformat()
            }, f, indent=2)
            
        # Update in-memory cache
        global OUI_MAPPING_CACHE
        OUI_MAPPING_CACHE = oui_map
        
        add_log("info", f"Vendor Database loaded from local file. {len(vendor_list)} vendors, {len(oui_map)} OUI mappings.", "system")
        
    except Exception as e:
        api_logger.error(f"Vendor loading failed: {e}")
        add_log("error", f"Vendor loading failed: {e}", "system")

# Initialize cache on module load
load_oui_cache()
# Also try to load from local file on startup to ensure we have data
if not OUI_MAPPING_CACHE:
    load_vendors_from_local_file()

@app.get("/api/vendors/search")
def search_vendors(q: str = Query("", alias="query"), refresh: bool = Query(False)):
    try:
        query = (q or "").strip().lower()
        
        # Load from file (or cache)
        vendor_list = []
        try:
            if os.path.exists(OUI_CACHE_FILE):
                with open(OUI_CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    vendor_list = data.get("vendors", [])
            else:
                # Try loading from local file if cache missing
                load_vendors_from_local_file()
                if os.path.exists(OUI_CACHE_FILE):
                     with open(OUI_CACHE_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        vendor_list = data.get("vendors", [])
        except:
            pass
            
        # Combine with current scan results
        vendors = set(vendor_list)
        for info in scanner.results.values():
            v = info.get("vendor")
            if isinstance(v, str) and v and v.lower() != "unknown":
                vendors.add(v)
        
        # Ensure curated list is always present
        curated = [
            "Cisco","Juniper","TP-Link","D-Link","Netgear","Ubiquiti","Huawei","ZTE","Hikvision","Dahua","Aruba",
            "Dell","HP","Synology","QNAP","MikroTik","Palo Alto","Fortinet","VMware","Apple","Raspberry Pi","Espressif","ASUS","Belkin","Samsung"
        ]
        for v in curated:
            vendors.add(v)
            
        final_list = sorted(list(vendors))
        
        if query:
            final_list = [v for v in final_list if query in v.lower()]
            
        return {"success": True, "data": final_list[:5000]}
    except Exception as e:
        api_logger.error(f"Error in search_vendors: {e}")
        return {"success": False, "error": str(e)}
@app.get("/api/devices/{device_id}")
def get_device(device_id: str):
    try:
        for ip, info in scanner.results.items():
            if info.get("mac") == device_id or ip == device_id:
                vulns_raw = info.get("vulnerabilities", [])
                try:
                    vulns = [format_vulnerability(v, ip) for v in vulns_raw]
                except Exception as ve:
                    api_logger.error(f"Error formatting vulnerabilities for device {ip}: {ve}")
                    vulns = []
                risk_level = "low"
                if any(v.get('severity') == 'critical' for v in vulns):
                    risk_level = "critical"
                elif any(v.get('severity') == 'high' for v in vulns):
                    risk_level = "high"
                elif any(v.get('severity') == 'medium' for v in vulns):
                    risk_level = "medium"
                raw_type = info.get("device_type", "unknown").lower()
                
                # Map ML/Fallback specific types to Frontend generic types
                type_mapping = {
                    'linux_device': 'computer',
                    'windows_device': 'computer',
                    'raspberry_pi': 'computer',
                    'esp_device': 'sensor',
                    'iot_device': 'sensor',
                    'web_server': 'computer',
                    'ssh_server': 'computer',
                    'metasploitable': 'computer',
                    'generic_device': 'unknown'
                }
                if raw_type in type_mapping:
                    raw_type = type_mapping[raw_type]

                valid_types = ['router', 'switch', 'camera', 'sensor', 'thermostat', 'smart_speaker', 'smart_tv', 'computer', 'phone', 'printer', 'nas', 'unknown', 'cant_determine']
                device_type = raw_type if raw_type in valid_types else 'unknown'
                
                # Resolve vendor from OUI if unknown
                vendor = info.get("vendor", "Unknown")
                mac = info.get("mac", "Unknown")
                if (not vendor or vendor.lower() == "unknown") and mac and mac.lower() != "unknown":
                    vendor = resolve_vendor_from_oui(mac)
                    if vendor != "Unknown":
                        scanner.results[ip]["vendor"] = vendor
                
                raw_ports = info.get("ports", [])
                processed_ports = []
                services_list = []
                for p in raw_ports:
                    if isinstance(p, dict):
                        port_num = int(p.get('port', 0))
                        service = p.get('service', 'unknown')
                        processed_ports.append({
                            "number": port_num,
                            "protocol": "tcp",
                            "service": service,
                            "state": "open",
                            "product": p.get("product") or "",
                            "version": p.get("version") or ""
                        })
                        services_list.append(service)
                    elif isinstance(p, (int, str)):
                        try:
                            port_num = int(p)
                            processed_ports.append({"number": port_num, "protocol": "tcp", "service": "unknown", "state": "open"})
                            services_list.append(str(port_num))
                        except:
                            pass
                return {
                    "success": True,
                    "data": {
                        "id": info.get("mac", ip),
                        "ip": ip,
                        "mac": info.get("mac", "Unknown"),
                        "vendor": info.get("vendor", "Unknown"),
                        "hostname": info.get("hostname", ip),
                        "type": device_type,
                        "riskLevel": risk_level,
                        "status": "online",
                        "lastSeen": info.get("last_seen", datetime.now().isoformat()),
                        "firstSeen": info.get("first_seen", datetime.now().isoformat()),
                        "os": info.get("os_match", "Unknown"),
                        "services": services_list,
                        "ports": processed_ports,
                        "vulnerabilities": vulns
                    }
                }
        return {"success": False, "error": "Device not found"}
    except Exception as e:
        api_logger.error(f"Error in get_device: {e}")
        return {"success": False, "error": str(e)}
@app.post("/api/auth/login")
def login(creds: LoginCredentials, background_tasks: BackgroundTasks):
    if creds.username == "admin" and creds.password == "admin123":
        add_log("info", f"User {creds.username} logged in", "auth")
        
        # Vendor database is now loaded from local file on startup
        
        return {
            "success": True, 
            "data": {
                "token": "mock-jwt-token-12345", 
                "user": {"id": "1", "username": "admin", "role": "admin"}
            }
        }
    add_log("warning", f"Failed login attempt for {creds.username}", "auth")
    return {"success": False, "error": "Invalid credentials"}
@app.get("/api/dashboard/stats")
def get_stats():
    total = len(scanner.results)
    critical_vulns = 0
    high_vulns = 0
    medium_vulns = 0
    low_vulns = 0
    vulnerable_devices = 0
    anomalies_detected = 0
    for d in scanner.results.values():
        # Check for anomalies
        if d.get("anomaly_detection", {}).get("is_anomaly", False):
            anomalies_detected += 1

        vulns = d.get("vulnerabilities", [])
        if vulns:
            vulnerable_devices += 1
            for v in vulns:
                severity = v.get("severity", "").upper()
                if severity == "CRITICAL":
                    critical_vulns += 1
                elif severity == "HIGH":
                    high_vulns += 1
                elif severity == "MEDIUM":
                    medium_vulns += 1
                elif severity == "LOW":
                    low_vulns += 1
    return {
        "success": True,
        "data": {
            "totalDevices": total,
            "vulnerableDevices": vulnerable_devices,
            "activeScans": 1 if scanner.is_scanning else 0,
            "criticalVulnerabilities": critical_vulns,
            "highVulnerabilities": high_vulns,
            "mediumVulnerabilities": medium_vulns,
            "lowVulnerabilities": low_vulns,
            "anomaliesDetected": anomalies_detected,
            "lastScanTime": datetime.now().isoformat()
        }
    }
@app.get("/api/dashboard/activity")
def get_activity():
    return {"success": True, "data": activity_log}
@app.get("/api/logs")
def get_logs():
    return {"success": True, "data": system_logs}

@app.get("/api/debug/log")
def download_debug_log(background_tasks: BackgroundTasks):
    log_file = "backend_debug.log"
    if not os.path.exists(log_file):
        return {"success": False, "error": "Log file not found"}
    
    # Create a temporary file to avoid locking issues
    try:
        fd, temp_path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        shutil.copy2(log_file, temp_path)
        
        # Schedule cleanup
        background_tasks.add_task(os.remove, temp_path)
        
        return FileResponse(temp_path, media_type="text/plain", filename="backend_debug.log")
    except Exception as e:
        api_logger.error(f"Failed to prepare log file for download: {e}")
        return {"success": False, "error": f"Failed to prepare log file: {str(e)}"}

@app.get("/api/reports")
def get_reports():
    reports_dir = "reports"
    if not os.path.exists(reports_dir):
        return {"success": True, "data": []}
    reports = []
    for filename in os.listdir(reports_dir):
        if filename.endswith(".json"):
            filepath = os.path.join(reports_dir, filename)
            try:
                stat = os.stat(filepath)
                created_time = datetime.fromtimestamp(stat.st_ctime).isoformat()
                with open(filepath, 'r') as f:
                    data = json.load(f)
                scan_info = data.get("scan_info", {})
                summary = data.get("summary", {})
                vuln_summary = summary.get("vulnerabilities", {})
                vuln_severity = vuln_summary.get("by_severity", {})
                reports.append({
                    "id": filename,
                    "name": filename,
                    "timestamp": scan_info.get("start_time", created_time),
                    "mode": scan_info.get("type", "quick"),
                    "status": "completed",
                    "summary": {
                        "totalDevices": data.get("total_devices", summary.get("total_devices", 0)),
                        "totalVulnerabilities": vuln_summary.get("total", summary.get("total_vulnerabilities", 0)),
                        "criticalVulnerabilities": vuln_severity.get("CRITICAL", summary.get("critical_vulns", 0)),
                        "highVulnerabilities": vuln_severity.get("HIGH", summary.get("high_vulns", 0))
                    }
                })
            except Exception as e:
                api_logger.error(f"Error reading report {filename}: {e}")
                continue
    reports.sort(key=lambda x: x["timestamp"], reverse=True)
    return {"success": True, "data": reports}
@app.get("/api/reports/{filename}")
def get_report(filename: str):
    reports_dir = "reports"
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    filepath = os.path.join(reports_dir, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return {"success": True, "data": data}
    except Exception as e:
        api_logger.error(f"Error reading report content {filename}: {e}")
        raise HTTPException(status_code=500, detail="Error reading report")
@app.get("/api/reports/{filename}/pdf")
def get_report_pdf(filename: str):
    reports_dir = "reports"
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    # Ensure we are working with the base filename (assuming input is the JSON filename)
    base_name = filename
    if filename.endswith(".json"):
        base_name = filename[:-5]
    
    json_path = os.path.join(reports_dir, f"{base_name}.json")
    pdf_path = os.path.join(reports_dir, f"{base_name}.pdf")
    
    if not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        # Generate PDF if it doesn't exist
        if not os.path.exists(pdf_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
            scanner.generate_pdf_report(data, pdf_path)
            
        return FileResponse(pdf_path, media_type="application/pdf", filename=f"{base_name}.pdf")
    except Exception as e:
        api_logger.error(f"Error generating/serving PDF for {filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating PDF: {str(e)}")

@app.delete("/api/reports/{filename}")
def delete_report(filename: str):
    reports_dir = "reports"
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    filepath = os.path.join(reports_dir, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
        
    try:
        os.remove(filepath)
        add_activity("report_deleted", f"Report {filename} deleted", "warning")
        return {"success": True, "message": "Report deleted successfully"}
    except Exception as e:
        api_logger.error(f"Error deleting report {filename}: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting report: {str(e)}")

@app.delete("/api/devices/{device_id}")
def delete_device(device_id: str):
    try:
        # Check if device exists in scanner results
        device_found = False
        target_ip = None
        
        # Try to find by IP or MAC
        if device_id in scanner.results:
            target_ip = device_id
            device_found = True
        else:
            for ip, info in scanner.results.items():
                if info.get("mac") == device_id:
                    target_ip = ip
                    device_found = True
                    break
        
        if device_found and target_ip:
            del scanner.results[target_ip]
            add_activity("device_deleted", f"Device {target_ip} removed from inventory", "warning")
            return {"success": True, "message": "Device deleted successfully"}
        
        return {"success": False, "error": "Device not found"}
    except Exception as e:
        api_logger.error(f"Error deleting device {device_id}: {e}")
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    import subprocess
    import re
    
    # Automatic Port Cleanup
    print("Checking for existing processes on port 8000...")
    try:
        # Check for process using port 8000
        netstat_output = subprocess.check_output("netstat -ano | findstr :8000", shell=True).decode()
        pids = set()
        for line in netstat_output.splitlines():
            if "LISTENING" in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    pids.add(pid)
        
        if pids:
            for pid in pids:
                if pid != "0":
                    print(f"Killing process {pid} using port 8000...")
                    subprocess.run(f"taskkill /PID {pid} /F", shell=True)
            print("Port 8000 cleared.")
        else:
            print("Port 8000 is free.")
            
    except subprocess.CalledProcessError:
        # findstr returns error if no match found, which means port is free
        print("Port 8000 is free.")
    except Exception as e:
        print(f"Warning during port cleanup: {e}")

    # reload=False prevents spawning a child process, ensuring only one process runs
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=False)
