"""
IoT Security Scanner - With AI-Based Features
"""
import json
import logging
import subprocess
import sys
import os
import glob
import socket
import platform
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import time
import traceback
import numpy as np
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.bool_, bool)):
            return bool(obj)
        return super().default(obj)
logger = logging.getLogger(__name__)
try:
    from config import NVD_API_KEY, SCAN_CONFIG, DEVICE_CLASSIFICATION, MAC_OUI_MAPPING
except ImportError as e:
    logger.error(f"Error importing config: {e}")
    print(f"Warning: config.py not found. Creating default configuration...")
    NVD_API_KEY = ""
    SCAN_CONFIG = {}
    DEVICE_CLASSIFICATION = {}
    MAC_OUI_MAPPING = {}
try:
    from iot_security.discovery import NetworkDiscovery
    from iot_security.nmap_scanner import NmapScanner
    from iot_security.vulnerability_checker import VulnerabilityChecker
    from iot_security.ai_classifier import AIDeviceClassifier
    from iot_security.anomaly_detector import AnomalyDetector
    AI_MODULES_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Error importing AI modules: {e}")
    print(f"Warning: AI modules not available. Some features will be disabled.")
    try:
        from iot_security.discovery import NetworkDiscovery
        from iot_security.nmap_scanner import NmapScanner
        from iot_security.vulnerability_checker import VulnerabilityChecker
        AI_MODULES_AVAILABLE = False
    except ImportError as e:
        logger.error(f"Error importing core modules: {e}")
        print(f"Error: Could not import required modules.")
        print(f"Make sure you have the iot_security directory with all required files.")
        sys.exit(1)
class IoTSecurityScanner:
    """Main scanner class with AI features"""
    def __init__(self):
        self.discovery = NetworkDiscovery()
        self.nmap_scanner = NmapScanner()
        self.vuln_checker = VulnerabilityChecker(api_key=NVD_API_KEY)
        if AI_MODULES_AVAILABLE:
            try:
                print("\n" + "=" * 40)
                print("INITIALIZING AI MODULES")
                print("=" * 40)
                classifier_path = "models/device_classifier_iot23.pkl"
                anomaly_path = "models/anomaly_detector_iot23.pkl"
                trained_models_exist = os.path.exists(classifier_path) and os.path.exists(anomaly_path)
                if trained_models_exist:
                    logger.info("Loading trained IoT-23 AI models...")
                    print(" Looking for trained IoT-23 AI models...")
                    self.ai_classifier = AIDeviceClassifier(model_path=classifier_path)
                    self.anomaly_detector = AnomalyDetector(model_path=anomaly_path)
                    self.ai_enabled = True
                    logger.info(" AI modules loaded with trained IoT-23 models")
                    print(" AI modules loaded with trained IoT-23 models")
                    if self.ai_classifier.model is not None:
                        print(f"  Device Classifier:  Loaded")
                        if hasattr(self.ai_classifier.model, 'n_estimators'):
                            print(f"    - Estimators: {self.ai_classifier.model.n_estimators}")
                    else:
                        print(f"  Device Classifier:  Failed to load")
                    if self.anomaly_detector.model is not None:
                        print(f"  Anomaly Detector:  Loaded")
                        if hasattr(self.anomaly_detector.model, 'n_estimators'):
                            print(f"    - Estimators: {self.anomaly_detector.model.n_estimators}")
                    else:
                        print(f"  Anomaly Detector:  Failed to load")
                else:
                    logger.warning("Trained IoT-23 models not found. Using default models.")
                    print("  Trained IoT-23 models not found. Using default models.")
                    self.ai_classifier = AIDeviceClassifier()
                    self.anomaly_detector = AnomalyDetector()
                    self.ai_enabled = True
                    logger.info("AI modules initialized with default models")
                    print(" AI modules initialized with default models")
            except Exception as e:
                logger.warning(f"AI modules failed to initialize: {e}")
                print(f" AI modules failed to initialize: {e}")
                self.ai_classifier = None
                self.anomaly_detector = None
                self.ai_enabled = False
        else:
            self.ai_classifier = None
            self.anomaly_detector = None
            self.ai_enabled = False
        self.results = {}
        self.selected_interface = None
        self.is_scanning = False
        self.should_stop = False
        self.scan_progress = 0
        self.current_scan_device = None
        self.oui_cache = {}
        self.load_oui_cache()

    def load_oui_cache(self):
        """Load OUI cache from ieee_vendors.json"""
        try:
            cache_file = os.path.join(os.path.dirname(__file__), "ieee_vendors.json")
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.oui_cache = data.get('oui_map', {})
                    logger.info(f"Loaded {len(self.oui_cache)} OUI entries from cache")
        except Exception as e:
            logger.error(f"Error loading OUI cache: {e}")

    def reset_state(self):
        """Reset scanner state for a fresh scan"""
        logger.info("Resetting scanner state for new scan...")
        self.results = {}
        self.overrides_cache = {}
        
        # Clear vulnerability cache
        if hasattr(self, 'vuln_checker'):
            self.vuln_checker.clear_cache()
            
        # Delete history files
        files_to_delete = ['iot_scanner.log', 'anomaly_history.json', 'devices.json']
        for file in files_to_delete:
            try:
                if os.path.exists(file):
                    os.remove(file)
                    logger.info(f"Deleted file: {file}")
            except Exception as e:
                logger.error(f"Error deleting {file}: {e}")

    def stop_scan(self):
        """Signal the scanner to stop"""
        self.should_stop = True
        logger.info("Stopping scan requested...")
    def get_available_interfaces(self) -> List[Tuple[str, str, str, str]]:
        """Get list of available network interfaces with their IPs and MACs"""
        interfaces = []
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addresses in addrs.items():
                if iface.lower().startswith(('docker', 'br-', 'veth', 'virbr', 'tap', 'tun')):
                    continue
                ipv4_address = None
                mac_address = "00:00:00:00:00:00"
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if not ip.startswith('127.') and not ip.startswith('169.254.'):
                            ipv4_address = ip
                    elif addr.family == psutil.AF_LINK:
                        mac_address = addr.address.replace('-', ':').lower()
                if ipv4_address:
                    status = "UP" if iface in stats and stats[iface].isup else "DOWN"
                    interfaces.append((iface, ipv4_address, status, mac_address))
            interfaces.sort(key=lambda x: x[0])
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
        return interfaces
    def nmap_host_discovery(self, network_range: str) -> Dict[str, Dict]:
        """Use Nmap ping scan to discover hosts that don't respond to ARP"""
        hosts = {}
        if not network_range:
            return hosts
        logger.info(f"Running Nmap host discovery on {network_range}")
        print(f"Running Nmap host discovery on {network_range}...")
        try:
            command = ['nmap', '-sn', '-n', network_range]
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                current_ip = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Nmap scan report for'):
                        parts = line.split()
                        if len(parts) >= 5:
                            current_ip = parts[4]
                    elif current_ip and 'MAC Address:' in line:
                        parts = line.split('MAC Address:')
                        if len(parts) > 1:
                            mac_part = parts[1].strip()
                            mac_parts = mac_part.split()
                            if len(mac_parts) > 0:
                                mac = mac_parts[0]
                                vendor = ' '.join(mac_parts[1:]) if len(mac_parts) > 1 else 'Unknown'
                                if self.discovery.is_non_device_address(current_ip):
                                    continue
                                hosts[current_ip] = {
                                    'mac': mac,
                                    'vendor': vendor,
                                    'first_seen': datetime.now().isoformat(),
                                    'last_seen': datetime.now().isoformat(),
                                    'discovery_method': 'nmap_ping'
                                }
                                current_ip = None
                    elif current_ip and 'Host is up' in line:
                        if not self.discovery.is_non_device_address(current_ip):
                            hosts[current_ip] = {
                                'mac': 'Unknown',
                                'vendor': 'Unknown',
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                                'discovery_method': 'nmap_ping_no_mac'
                            }
                        current_ip = None
        except subprocess.TimeoutExpired:
            logger.warning(f"Nmap host discovery timed out for {network_range}")
        except Exception as e:
            logger.error(f"Error in Nmap host discovery: {e}")
        logger.info(f"Nmap host discovery found {len(hosts)} hosts")
        return hosts
    def select_interface(self) -> Optional[Tuple[str, str]]:
        """Let user select which interface to scan"""
        interfaces = self.get_available_interfaces()
        if not interfaces:
            print("\n No network interfaces found!")
            return None
        print("\n" + "=" * 60)
        print("AVAILABLE NETWORK INTERFACES")
        print("=" * 60)
        print("\nNo. | Interface Name         | IP Address        | Status")
        print("-" * 60)
        for i, (iface, ip, status, _) in enumerate(interfaces, 1):
            print(f"{i:3} | {iface:22} | {ip:16} | {status}")
        print("\nSelect interface to scan:")
        print("  [1-{}] - Select interface".format(len(interfaces)))
        print("  [a]    - Scan ALL interfaces")
        print("  [m]    - Manually enter network range")
        print("  [q]    - Quit")
        while True:
            choice = input("\nEnter choice: ").strip().lower()
            if choice == 'q':
                return None
            elif choice == 'a':
                print("Scanning all interfaces...")
                return ("ALL", "0.0.0.0")
            elif choice == 'm':
                network = input("Enter network in CIDR format (e.g., 192.168.1.0/24): ").strip()
                if network:
                    return ("MANUAL", network)
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    selected = interfaces[idx]
                    print(f"\n Selected: {selected[0]} ({selected[1]})")
                    return (selected[0], selected[1])
            print("Invalid choice. Please try again.")
    def filter_devices_by_network(self, devices: Dict, network_cidr: str, extra_subnets: List[str] = None) -> Dict:
        """Quick filter to remove foreign network devices and non-device addresses"""
        filtered = {}
        if not devices:
            return filtered
            
        # Parse main network
        prefixes = []
        if network_cidr:
            if '/' in network_cidr:
                network_ip = network_cidr.split('/')[0]
                prefixes.append(network_ip.rsplit('.', 1)[0] + ".")
            else:
                prefixes.append(network_cidr.rsplit('.', 1)[0] + ".")
                
        # Parse extra subnets
        if extra_subnets:
            for subnet in extra_subnets:
                if '/' in subnet:
                    subnet_ip = subnet.split('/')[0]
                    prefixes.append(subnet_ip.rsplit('.', 1)[0] + ".")
                else:
                    prefixes.append(subnet.rsplit('.', 1)[0] + ".")
        
        for ip, info in devices.items():
            if ip.startswith(("224.", "225.", "226.", "227.", "228.", "229.", 
                              "230.", "231.", "232.", "233.", "234.", "235.",
                              "236.", "237.", "238.", "239.")):
                logger.debug(f"Filtered out multicast address: {ip}")
                continue
            if ip == "255.255.255.255" or ip.endswith(".255"):
                logger.debug(f"Filtered out broadcast address: {ip}")
                continue
            if ip.startswith("169.254."):
                logger.debug(f"Filtered out link-local address: {ip}")
                continue
            if ip.startswith("127."):
                logger.debug(f"Filtered out loopback address: {ip}")
                continue
                
            # Check if IP matches any allowed prefix
            matched = False
            for prefix in prefixes:
                if ip.startswith(prefix):
                    matched = True
                    break
            
            if matched:
                filtered[ip] = info
                logger.debug(f"Included device: {ip}")
            else:
                logger.debug(f"Filtered out {ip} - not in allowed networks")
        return filtered

    def run_scan(self, scan_mode: int = 1, interface_choice: str = None, extra_subnets: List[str] = None):
        """Run scan with AI features"""
        self.is_scanning = True
        self.should_stop = False
        self.scan_progress = 0
        self.results = {}
        # Load any manual overrides persisted from previous runs
        try:
            overrides_path = self.discovery.output_file if hasattr(self, "discovery") else os.path.join(os.path.dirname(__file__), "devices.json")
            with open(overrides_path, 'r') as f:
                self.overrides_cache = json.load(f)
        except Exception:
            self.overrides_cache = {}
        
        # Use config subnets if not provided
        if extra_subnets is None:
            extra_subnets = SCAN_CONFIG.get('routed_subnets', [])
        
        # If extra_subnets provided, log them
        if extra_subnets:
            logger.info(f"Extra subnets for scanning: {extra_subnets}")
            print(f"Included routed subnets: {extra_subnets}")
        # Track scan mode name for API/dashboard/reporting
        try:
            if scan_mode == 1:
                self.scan_mode_name = "quick"
            elif scan_mode == 2:
                self.scan_mode_name = "deep"
            elif scan_mode == 3:
                self.scan_mode_name = "comprehensive"
            else:
                self.scan_mode_name = "quick"
        except Exception:
            self.scan_mode_name = "quick"
        try:
            print("\n" + "=" * 60)
            print("IoT Security Scanner v3.0 - AI Enhanced")
            print("=" * 60)
            print("Features: Network Discovery | Vulnerability Scanning")
            if self.ai_enabled:
                print("          AI Classification | Anomaly Detection")
            print("=" * 60)
            logger.info("=" * 60)
            logger.info("IoT Security Scanner v3.0 - Starting Scan")
            logger.info("=" * 60)
            print("\nStep 0: Interface Selection")
            print("-" * 40)
            if interface_choice:
                if interface_choice == "list":
                    interfaces = self.get_available_interfaces()
                    print("\nAvailable Interfaces:")
                    for iface, ip, status, _ in interfaces:
                        print(f"  {iface}: {ip} ({status})")
                    return
                else:
                    interfaces = self.get_available_interfaces()
                    selected = None
                    for iface, ip, status, _ in interfaces:
                        if interface_choice.lower() in iface.lower() or interface_choice == ip:
                            selected = (iface, ip, status)
                            break
                    if selected:
                        print(f"Using interface: {selected[0]} ({selected[1]})")
                        self.selected_interface = selected[0]
                        network_range = self.discovery.get_network_range_for_interface(selected[0])
                    else:
                        print(f"Interface '{interface_choice}' not found.")
                        logger.error(f"Interface '{interface_choice}' not found.")
                        return
            else:
                # In API mode (implied if we are here without interface_choice but blocking input is bad),
                # we should probably return or pick a default if possible.
                # But typically run_scan is called with interface_choice from API.
                # If called from CLI without arguments, it might still be interactive.
                # We can check if we are in a non-interactive environment or just let it be if it's CLI.
                # For safety in this context, we'll assume if it's not passed, we can't guess.
                # However, the original code called select_interface().
                pass 
                # Keeping original behavior for no-arg call (CLI usage), but preventing it for failed arg match.
                selected = self.select_interface()
                if not selected:
                    return
                self.selected_interface = selected[0]
                network_range = selected[1] if selected[0] == "MANUAL" else None
            if network_range:
                print(f"\nTarget Network: {network_range}")
                logger.info(f"Target Network: {network_range}")
            print("\nStep 1: Network Discovery")
            print("-" * 40)
            logger.info("\nStep 1: Network Discovery")
            logger.info("-" * 40)
            self.discovery.print_network_info()
            local_ips = [ip for _, ip in self.discovery.network_utils.get_local_ipv4_addresses()]
            logger.info(f"Local IPs to exclude: {local_ips}")
            devices = {}
            if scan_mode == 1:  
                print(f"Mode: Quick Scan on {self.selected_interface}")
                logger.info(f"Mode: Quick Scan on {self.selected_interface}")
                if self.selected_interface == "ALL":
                    devices = self.scan_all_interfaces(prefer_passive=False, extra_subnets=extra_subnets)
                elif self.selected_interface == "MANUAL":
                    devices = self.discovery.scan_specific_network(network_range)
                else:
                    devices = self.discovery.discover_devices_on_interface(
                        self.selected_interface, prefer_passive=False, extra_subnets=extra_subnets
                    )
            elif scan_mode == 2:  
                print(f"Mode: Deep Scan on {self.selected_interface}")
                logger.info(f"Mode: Deep Scan on {self.selected_interface}")
                if self.selected_interface == "ALL":
                    devices = self.scan_all_interfaces(prefer_passive=False, extra_subnets=extra_subnets)
                elif self.selected_interface == "MANUAL":
                    devices = self.discovery.scan_specific_network(network_range)
                else:
                    devices = self.discovery.discover_devices_on_interface(
                        self.selected_interface, prefer_passive=False, extra_subnets=extra_subnets
                    )
            elif scan_mode == 3:  
                print(f"Mode: Comprehensive on {self.selected_interface}")
                logger.info(f"Mode: Comprehensive on {self.selected_interface}")
                if self.selected_interface == "ALL":
                    devices = self.scan_all_interfaces(comprehensive=True, extra_subnets=extra_subnets)
                elif self.selected_interface == "MANUAL":
                    devices = self.discovery.scan_specific_network(network_range)
                else:
                    devices = self.discovery.comprehensive_scan_on_interface(
                        self.selected_interface, extra_subnets=extra_subnets
                    )
            if len(devices) < 3 and self.selected_interface not in ["ALL", "MANUAL"]:
                print("\nFew devices found via ARP, trying Nmap ping discovery...")
                logger.info("Few devices found via ARP, trying Nmap ping discovery...")
                iface_network_range = self.discovery.get_network_range_for_interface(self.selected_interface)
                if iface_network_range:
                    nmap_hosts = self.nmap_host_discovery(iface_network_range)
                    for ip, info in nmap_hosts.items():
                        if ip not in devices:
                            devices[ip] = info
                            print(f"  Added via Nmap ping: {ip}")
                            logger.info(f"Added via Nmap ping: {ip}")
            for local_ip in local_ips:
                if local_ip in devices:
                    print(f"Removing local IP {local_ip} from results")
                    logger.info(f"Removing local IP {local_ip} from results")
                    del devices[local_ip]
            if self.selected_interface not in ["ALL", "MANUAL"] and network_range:
                print(f"\nFiltering devices to only include those in {network_range}")
                if extra_subnets:
                    print(f"And included extra subnets: {extra_subnets}")
                logger.info(f"Filtering devices to only include those in {network_range} and {extra_subnets}")
                devices = self.filter_devices_by_network(devices, network_range, extra_subnets)
            if not devices:
                print("\n No devices found on selected interface!")
                print(f"Interface: {self.selected_interface}")
                if network_range:
                    print(f"Network: {network_range}")
                print("Check if:")
                print("  1. Interface is connected and active")
                print("  2. There are other devices on the network")
                print("  3. Firewall isn't blocking ARP requests")
                logger.error(f"No devices found on interface: {self.selected_interface}")
                return
            print(f"\nDiscovery complete: {len(devices)} devices found")
            logger.info(f"Discovery complete: {len(devices)} devices found")
            for ip, info in devices.items():
                vendor = info.get('vendor', 'Unknown')
                discovery_method = info.get('discovery_method', 'unknown')
                print(f"  - {ip} ({vendor}) [{discovery_method}]")
                logger.info(f"  - {ip} ({vendor}) [{discovery_method}]")
            self.results = devices.copy()
            print("\nStep 2: Device Scanning")
            print("-" * 40)
            logger.info("\nStep 2: Device Scanning")
            logger.info("-" * 40)
            for ip, device_info in devices.items():
                self.current_scan_device = ip
                if self.should_stop:
                    logger.info("Scan stopped by user")
                    print("\n Scan stopped by user")
                    break
                print(f"\n[+] Scanning device: {ip}")
                logger.info(f"\n[+] Scanning device: {ip}")
                print(f"   MAC: {device_info.get('mac', 'Unknown')}")
                logger.info(f"   MAC: {device_info.get('mac', 'Unknown')}")
                print(f"   Vendor: {device_info.get('vendor', 'Unknown')}")
                logger.info(f"   Vendor: {device_info.get('vendor', 'Unknown')}")
                mac = device_info.get('mac', '')
                if mac and mac != 'Unknown':
                    # Try local OUI cache first (more comprehensive)
                    clean_mac = mac.replace(":", "").replace("-", "").upper()
                    if len(clean_mac) >= 6:
                        oui = clean_mac[:6]
                        if oui in self.oui_cache:
                            device_info['vendor'] = self.oui_cache[oui]
                            print(f"   Identified via OUI Cache: {self.oui_cache[oui]}")
                            logger.info(f"   Identified via OUI Cache: {self.oui_cache[oui]}")
                    
                    # Fallback to config mapping if not found in cache
                    if device_info.get('vendor', 'Unknown') == 'Unknown':
                        oui_prefix = mac[:8].lower()
                        if oui_prefix in MAC_OUI_MAPPING:
                            device_info['vendor'] = MAC_OUI_MAPPING[oui_prefix]
                            print(f"   Identified via Config OUI: {MAC_OUI_MAPPING[oui_prefix]}")
                            logger.info(f"   Identified via Config OUI: {MAC_OUI_MAPPING[oui_prefix]}")
                # Apply manual overrides if present
                try:
                    override = None
                    if isinstance(self.overrides_cache, dict):
                        override = self.overrides_cache.get(ip)
                        if not override and mac and mac != 'Unknown':
                            # Fallback: find by MAC match
                            for ov_ip, ov_info in self.overrides_cache.items():
                                if isinstance(ov_info, dict) and ov_info.get('mac') == mac:
                                    override = ov_info
                                    break
                    if override:
                        if override.get('vendor_manual'):
                            device_info['vendor'] = override['vendor_manual']
                        if override.get('device_type_manual'):
                            device_info['device_type'] = override['device_type_manual']
                except Exception:
                    pass
                nmap_results = {}
                enhanced_scans = {}
                if scan_mode == 1:  
                    nmap_results = self.nmap_scanner.scan_device(ip, quick_scan=True)
                elif scan_mode == 2:  
                    nmap_results = self.nmap_scanner.scan_device(ip, quick_scan=False)
                    enhanced_scans['udp_scan'] = self.nmap_scanner.scan_udp_ports(ip)
                    enhanced_scans['http_headers'] = self.nmap_scanner.check_http_headers(ip)
                elif scan_mode == 3:  
                    nmap_results = self.nmap_scanner.scan_device(ip, quick_scan=False)
                    enhanced_scans = self.nmap_scanner.enhanced_device_scan(ip)
                print(f"   AI Analysis: ", end="")
                if self.ai_enabled and self.ai_classifier:
                    print(f"Classifying with AI...")
                    device_type, ai_confidence, ai_details = self.ai_classifier.classify_device(
                        device_info, nmap_results, enhanced_scans
                    )
                    device_info['device_type'] = device_type
                    device_info['ai_classification'] = {
                        'confidence': ai_confidence,
                        'details': ai_details,
                        'method': 'ml'
                    }
                    print(f"   Type: {device_type} (AI confidence: {ai_confidence:.2f})")
                    logger.info(f"   AI Classification: {device_type} (confidence: {ai_confidence:.2f})")
                    if self.anomaly_detector:
                        anomaly_result = self.anomaly_detector.detect_anomalies(
                            ip, device_info, nmap_results
                        )
                        device_info['anomaly_detection'] = anomaly_result
                        if anomaly_result['is_anomalous']:
                            print(f"     ANOMALY DETECTED! Score: {anomaly_result['anomaly_score']:.2f}")
                            for reason in anomaly_result['reasons'][:2]:
                                print(f"      - {reason}")
                            logger.warning(f"   Anomaly detected for {ip}: {anomaly_result}")
                        else:
                            print(f"    Normal behavior detected")
                else:
                    device_type = self.classify_device(device_info, nmap_results, enhanced_scans)
                    device_info['device_type'] = device_type
                    print(f"   Type: {device_type} (Rule-based)")
                    logger.info(f"   Classification: {device_type} (rule-based)")
                device_info.update({
                    'ip': ip,
                    'interface': self.selected_interface,
                    'ports': nmap_results.get('ports', []),
                    'services': nmap_results.get('services', {}),
                    'os_info': nmap_results.get('os_info', {}),
                    'enhanced_scans': enhanced_scans,
                    'scan_timestamp': datetime.now().isoformat()
                })
                if nmap_results.get('services') or enhanced_scans:
                    print(f"   Checking vulnerabilities...")
                    logger.info(f"   Checking vulnerabilities...")
                    if not NVD_API_KEY:
                        logger.debug("No NVD API key configured, only checking port risks")
                    vulnerabilities = self.vuln_checker.check_device_vulnerabilities(
                        device_info, nmap_results
                    )
                    if vulnerabilities:
                        device_info['vulnerabilities'] = vulnerabilities
                        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                        for vuln in vulnerabilities:
                            severity = vuln.get('severity', 'LOW').upper()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                        summary_parts = []
                        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                            if severity_counts[sev] > 0:
                                summary_parts.append(f"{severity_counts[sev]} {sev}")
                        if summary_parts:
                            summary = f" ({', '.join(summary_parts)})"
                        else:
                            summary = ""
                        print(f"    Found {len(vulnerabilities)} vulnerabilities{summary}")
                        logger.info(f"   Found {len(vulnerabilities)} vulnerabilities{summary}")
                        for vuln in vulnerabilities:
                            severity = vuln.get('severity', '').upper()
                            if severity in ['CRITICAL', 'HIGH']:
                                title = vuln.get('title', 'Unknown')
                                if len(title) > 60:
                                    title = title[:57] + "..."
                                print(f"     [{severity}] {title}")
                                logger.warning(f"     [{severity}] {vuln.get('title', 'Unknown')}")
                    else:
                        print("    No high-risk vulnerabilities found")
                        logger.info("   No high-risk vulnerabilities found")
                else:
                    print("    No services found for vulnerability check")
                    logger.info("   No services found for vulnerability check")
                self.results[ip] = device_info
                time.sleep(0.5)  
            self.current_scan_device = None
            self.scan_progress = 95
            print("Step 3: Generating Reports")
            print("-" * 40)
            logger.info("Step 3: Generating Reports")
            logger.info("-" * 40)
            self.generate_reports()
            self.print_summary()
            print("Scan Complete!")
            print(f"   Scanned {len(self.results)} devices on {self.selected_interface}")
            if network_range:
                print(f"   Network: {network_range}")
            if self.ai_enabled:
                print(f"   AI Features: Classification & Anomaly Detection")
            logger.info("[+] Scan Complete!")
            logger.info(f"   Scanned {len(self.results)} devices on {self.selected_interface}")
            self.scan_progress = 100
        except Exception as e:
            logger.error(f"Error in run_scan: {e}")
            logger.error(traceback.format_exc())
            print(f"Error during scan: {e}")
            print("Check iot_scanner.log for details")
        finally:
            self.is_scanning = False
    def scan_all_interfaces(self, prefer_passive: bool = True, comprehensive: bool = False, extra_subnets: List[str] = None) -> Dict:
        """Scan all available interfaces"""
        all_devices = {}
        interfaces = self.get_available_interfaces()
        for iface, ip, status, _ in interfaces:
            if status == "UP":
                print(f"Scanning interface: {iface} ({ip})")
                logger.info(f"Scanning interface: {iface} ({ip})")
                try:
                    if comprehensive:
                        devices = self.discovery.comprehensive_scan_on_interface(iface, extra_subnets=extra_subnets)
                    else:
                        devices = self.discovery.discover_devices_on_interface(iface, prefer_passive, extra_subnets=extra_subnets)
                    if devices:
                        network_range = self.discovery.get_network_range_for_interface(iface)
                        print(f"  Found {len(devices)} devices on {iface} ({network_range})")
                        logger.info(f"  Found {len(devices)} devices on {iface} ({network_range})")
                        if len(devices) < 3 and network_range:
                            print(f"  Few devices via ARP, trying Nmap ping on {network_range}...")
                            nmap_hosts = self.nmap_host_discovery(network_range)
                            for host_ip, host_info in nmap_hosts.items():
                                if host_ip not in devices:
                                    devices[host_ip] = host_info
                                    print(f"    Added via Nmap ping: {host_ip}")
                        if network_range:
                            devices = self.filter_devices_by_network(devices, network_range, extra_subnets)
                            print(f"  After filtering: {len(devices)} devices in network {network_range}")
                        all_devices.update(devices)
                    else:
                        print(f"  No devices found on {iface}")
                        logger.info(f"  No devices found on {iface}")
                except Exception as e:
                    logger.error(f"Error scanning interface {iface}: {e}")
                    print(f"  Error scanning {iface}: {e}")
        return all_devices
    def classify_device(self, device_info: Dict, nmap_results: Dict, enhanced_scans: Dict) -> str:
        """Classify device type based on all available information"""
        vendor = device_info.get('vendor', '').lower()
        mac = device_info.get('mac', '').lower()
        ports = [str(p.get('port', '')) for p in nmap_results.get('ports', [])]
        services = nmap_results.get('services', {})
        for service_name, service_info in services.items():
            if 'dnsmasq' in str(service_info).lower():
                return "Router/Gateway (DNS/DHCP Server)"
        udp_scan = enhanced_scans.get('udp_scan', {})
        if udp_scan.get('open_ports'):
            udp_ports = list(udp_scan['open_ports'].keys())
            if 161 in udp_ports or 162 in udp_ports:
                return "Network Device (SNMP)"
            if 1900 in udp_ports:
                return "UPnP Device"
            if 5353 in udp_ports:
                return "mDNS/Bonjour Device"
            if 5683 in udp_ports:
                return "IoT Device (CoAP)"
        if mac:
            oui = mac[:8]
            for oui_prefix, device_type in MAC_OUI_MAPPING.items():
                if oui_prefix in mac:
                    if "esp" in device_type.lower():
                        return "IoT Device (ESP32/ESP8266)"
                    elif "raspberry" in device_type.lower():
                        return "Raspberry Pi"
                    elif "vmware" in device_type.lower():
                        return "Virtual Machine"
                    elif "tp-link" in device_type.lower():
                        return "Router (TP-Link)"
                    elif "d-link" in device_type.lower():
                        return "Router (D-Link)"
                    elif "netgear" in device_type.lower():
                        return "Router (Netgear)"
        for service_name, service_info in services.items():
            service_name_lower = service_name.lower()
            if service_name_lower == 'http' or service_name_lower == 'https':
                product = str(service_info.get('product', '')).lower()
                if any(word in product for word in ['router', 'gateway', 'admin', 'webif']):
                    return "Router Web Interface"
            if service_name_lower == 'rtsp':
                return "IP Camera"
            if service_name_lower == 'upnp':
                return "UPnP Device"
            if service_name_lower == 'snmp':
                return "Network Device (SNMP)"
        if '53' in ports:
            return "DNS Server"
        if '80' in ports or '443' in ports:
            return "Web Server"
        if '22' in ports:
            return "SSH Server"
        if '23' in ports:
            return "Telnet Server (INSECURE)"
        if '21' in ports:
            return "FTP Server"
        if '554' in ports:
            return "IP Camera (RTSP)"
        if '37777' in ports:
            return "Security Camera (Dahua)"
        iot_protocols = enhanced_scans.get('iot_protocols', {})
        if iot_protocols:
            return f"IoT Device ({', '.join(iot_protocols.keys())})"
        if any(port.isdigit() and int(port) > 0 for port in ports):
            return "Network Device"
        if enhanced_scans:
            return "Network Device (UDP services only)"
        return "Unknown Device"
    def load_last_scan(self):
        """Load results from the most recent scan report"""
        try:
            if not os.path.exists('reports'):
                return False
            list_of_files = glob.glob('reports/*.json')
            if not list_of_files:
                return False
            latest_file = max(list_of_files, key=os.path.getctime)
            logger.info(f"Loading last scan from {latest_file}")
            print(f"Loading last scan from {latest_file}")
            with open(latest_file, 'r') as f:
                data = json.load(f)
            if 'devices' in data:
                self.results = data['devices']
                if 'scan_info' in data and 'interface' in data['scan_info']:
                    self.selected_interface = data['scan_info']['interface']
                return True
        except Exception as e:
            logger.error(f"Error loading last scan: {e}")
            return False
    def generate_reports(self):
        """Generate all reports"""
        if not self.results:
            print("\nNo devices to generate reports for")
            logger.warning("No devices to generate reports for")
            return
        try:
            nvd_status = "Active" if NVD_API_KEY else "Limited (Port-based only) - No API Key"
            scan_info = {
                'start_time': datetime.now().isoformat(),
                'type': self.scan_mode_name if hasattr(self, 'scan_mode_name') else 'quick',
                'interface': self.selected_interface,
                'nvd_status': nvd_status
            }
            report = {
                'scan_info': scan_info,
                'scan_date': datetime.now().isoformat(),
                'interface_scanned': self.selected_interface,
                'total_devices': len(self.results),
                'devices': self.results,
                'summary': self.generate_summary(),
                'recommendations': self.generate_recommendations(),
                'ai_enabled': self.ai_enabled
            }
            if not os.path.exists('reports'):
                os.makedirs('reports')
            timestamp = int(time.time())
            filename = f'reports/iot_scan_{self.selected_interface.replace(" ", "_")}_{timestamp}.json'
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, cls=CustomJSONEncoder)
            logger.info(f"Report generated: {filename}")
            print(f"\n Report generated: {filename}")
            text_filename = f'reports/iot_scan_{self.selected_interface.replace(" ", "_")}_{timestamp}_summary.txt'
            self.generate_text_report(report, text_filename)
            
            # PDF generation is now on-demand only
            # try:
            #     pdf_filename = f'reports/iot_scan_{self.selected_interface.replace(" ", "_")}_{timestamp}.pdf'
            #     self.generate_pdf_report(report, pdf_filename)
            #     print(f"  - {pdf_filename} (PDF Report)")
            #     logger.info(f"  - {pdf_filename} (PDF Report)")
            # except Exception as e:
            #     logger.warning(f"Could not generate PDF report: {e}")
            #     print(f"  - PDF generation skipped ({e})")
            
            self.cleanup_old_reports()

            print(f"\nReports saved:")
            print(f"  - {filename} (Detailed JSON)")
            print(f"  - {text_filename} (Human readable)")
            logger.info(f"Reports saved:")
            logger.info(f"  - {filename} (Detailed JSON)")
            logger.info(f"  - {text_filename} (Human readable)")
        except Exception as e:
            logger.error(f"Error generating reports: {e}")
            print(f"Error generating reports: {e}")

    def cleanup_old_reports(self, limit=10):
        """Keep only the latest N reports"""
        try:
            report_dir = 'reports'
            if not os.path.exists(report_dir):
                return
            
            # Get all JSON reports
            reports = glob.glob(os.path.join(report_dir, '*.json'))
            # Sort by modification time (newest first)
            reports.sort(key=os.path.getmtime, reverse=True)
            
            if len(reports) > limit:
                logger.info(f"Cleaning up old reports (keeping latest {limit})...")
                for old_report in reports[limit:]:
                    try:
                        # Delete JSON
                        os.remove(old_report)
                        logger.info(f"Deleted old report: {old_report}")
                        
                        # Delete corresponding TXT
                        txt_report = old_report.replace('.json', '_summary.txt')
                        if os.path.exists(txt_report):
                            os.remove(txt_report)
                            
                        # Delete corresponding PDF
                        pdf_report = old_report.replace('.json', '.pdf')
                        if os.path.exists(pdf_report):
                            os.remove(pdf_report)
                    except Exception as e:
                        logger.warning(f"Error deleting old report {old_report}: {e}")
        except Exception as e:
            logger.error(f"Error in cleanup_old_reports: {e}")

    def generate_pdf_report(self, report_data, filename):
        """Generate PDF report if fpdf is available"""
        try:
            from fpdf import FPDF
        except ImportError:
            raise ImportError("fpdf module not found. Install with: pip install fpdf")
        class PDF(FPDF):
            def header(self):
                self.set_font('Arial', 'B', 15)
                self.cell(0, 10, 'IoT Security Scan Report', 0, 1, 'C')
                self.ln(5)
            def footer(self):
                self.set_y(-15)
                self.set_font('Arial', 'I', 8)
                self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Date: {report_data['scan_date']}", ln=1, align='L')
        pdf.cell(200, 10, txt=f"Interface: {report_data['interface_scanned']}", ln=1, align='L')
        pdf.cell(200, 10, txt=f"Devices Found: {report_data['total_devices']}", ln=1, align='L')
        pdf.cell(200, 10, txt=f"NVD Status: {report_data['scan_info']['nvd_status']}", ln=1, align='L')
        pdf.ln(10)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, txt="Scan Summary", ln=1, align='L')
        pdf.set_font("Arial", size=12)
        summary = report_data['summary']
        pdf.cell(200, 10, txt=f"Vulnerable Devices: {summary.get('vulnerable_devices', 0)}", ln=1, align='L')
        pdf.cell(200, 10, txt=f"Critical Vulnerabilities: {summary['vulnerabilities']['by_severity'].get('CRITICAL', 0)}", ln=1, align='L')
        pdf.ln(10)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(200, 10, txt="Device List", ln=1, align='L')
        pdf.set_font("Arial", size=10)
        for ip, device in report_data['devices'].items():
            pdf.ln(5)
            name = device.get('vendor', 'Unknown')
            pdf.set_font("Arial", 'B', 10)
            pdf.cell(200, 5, txt=f"{ip} ({name})", ln=1, align='L')
            pdf.set_font("Arial", size=10)
            pdf.cell(200, 5, txt=f"  Type: {device.get('device_type', 'Unknown')}", ln=1, align='L')
            pdf.cell(200, 5, txt=f"  MAC: {device.get('mac', 'Unknown')}", ln=1, align='L')
            if 'vulnerabilities' in device:
                pdf.set_text_color(255, 0, 0)
                pdf.cell(200, 5, txt=f"  Vulnerabilities: {len(device['vulnerabilities'])} found", ln=1, align='L')
                pdf.set_text_color(0, 0, 0)
            else:
                pdf.set_text_color(0, 128, 0)
                pdf.cell(200, 5, txt=f"  No vulnerabilities found", ln=1, align='L')
                pdf.set_text_color(0, 0, 0)
        pdf.output(filename)
    def generate_summary(self) -> Dict:
        """Generate scan summary"""
        summary = {
            'device_types': {},
            'open_ports': {},
            'vendors': {},
            'vulnerabilities': {
                'total': 0,
                'by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            },
            'vulnerable_devices': 0,
            'ai_analysis': {
                'devices_classified': 0,
                'average_confidence': 0.0,
                'anomalies_detected': 0
            }
        }
        total_ai_confidence = 0
        ai_classified_count = 0
        for ip, device in self.results.items():
            dev_type = device.get('device_type', 'Unknown')
            summary['device_types'][dev_type] = summary['device_types'].get(dev_type, 0) + 1
            vendor = device.get('vendor', 'Unknown')
            summary['vendors'][vendor] = summary['vendors'].get(vendor, 0) + 1
            if 'vulnerabilities' in device:
                summary['vulnerable_devices'] += 1
                summary['vulnerabilities']['total'] += len(device['vulnerabilities'])
                for vuln in device['vulnerabilities']:
                    severity = vuln.get('severity', 'MEDIUM').upper()
                    if severity in summary['vulnerabilities']['by_severity']:
                        summary['vulnerabilities']['by_severity'][severity] += 1
            for port_info in device.get('ports', []):
                port = port_info.get('port')
                if port:
                    summary['open_ports'][str(port)] = summary['open_ports'].get(str(port), 0) + 1
            if 'ai_classification' in device:
                ai_classified_count += 1
                total_ai_confidence += device['ai_classification'].get('confidence', 0.0)
            if 'anomaly_detection' in device and device['anomaly_detection'].get('is_anomalous'):
                summary['ai_analysis']['anomalies_detected'] += 1
        if ai_classified_count > 0:
            summary['ai_analysis']['devices_classified'] = ai_classified_count
            summary['ai_analysis']['average_confidence'] = round(total_ai_confidence / ai_classified_count, 2)
        return summary
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = [
            f"SCAN INFORMATION:",
            f"Interface: {self.selected_interface}",
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"AI Enabled: {'Yes' if self.ai_enabled else 'No'}",
            f"",
            f"GENERAL SECURITY RECOMMENDATIONS:",
            f"1. Change default credentials on all devices",
            f"2. Update firmware regularly",
            f"3. Disable unnecessary services and ports",
            f"4. Use network segmentation for IoT devices",
            f"5. Enable firewall rules",
            f"6. Replace insecure protocols (Telnet, FTP) with SSH/SFTP",
            f"7. Monitor network for unusual activity",
            f"8. Regular security assessments",
            f""
        ]
        if self.ai_enabled:
            recommendations.append(f"AI-SPECIFIC INSIGHTS:")
            recommendations.append(f"1. Review AI-classified device types for accuracy")
            recommendations.append(f"2. Investigate any detected anomalies")
            recommendations.append(f"3. Train AI models with your specific network data")
            recommendations.append(f"")
        for ip, device in self.results.items():
            dev_type = device.get('device_type', '')
            vulnerabilities = device.get('vulnerabilities', [])
            anomaly_info = device.get('anomaly_detection', {})
            if 'Router' in dev_type or 'Gateway' in dev_type:
                recommendations.append(f"ROUTER {ip}:")
                recommendations.append("  - Change admin password from default")
                recommendations.append("  - Disable WPS (Wi-Fi Protected Setup)")
                recommendations.append("  - Enable WPA2/WPA3 encryption")
                recommendations.append("  - Disable remote administration")
                recommendations.append("  - Update router firmware")
                recommendations.append("")
            if 'Camera' in dev_type:
                recommendations.append(f"CAMERA {ip}:")
                recommendations.append("  - Change default admin password")
                recommendations.append("  - Disable UPnP if not needed")
                recommendations.append("  - Enable encryption for video streams")
                recommendations.append("  - Restrict access to specific IPs")
                recommendations.append("")
            if 'DNS Server' in dev_type:
                recommendations.append(f"DNS SERVER {ip}:")
                recommendations.append("  - Ensure DNS server is properly configured")
                recommendations.append("  - Implement DNSSEC if possible")
                recommendations.append("  - Rate limit DNS queries")
                recommendations.append("  - Disable recursion for external clients")
                recommendations.append("")
            if vulnerabilities:
                high_vulns = [v for v in vulnerabilities if v.get('severity', '').upper() in ['CRITICAL', 'HIGH']]
                if high_vulns:
                    recommendations.append(f"CRITICAL ISSUES for {ip}:")
                    for vuln in high_vulns[:2]:
                        recommendations.append(f"  - {vuln.get('title', 'Unknown')}")
                        recommendations.append(f"    Severity: {vuln.get('severity', 'Unknown')}")
                    recommendations.append("")
            if anomaly_info.get('is_anomalous'):
                recommendations.append(f"ANOMALY DETECTED for {ip}:")
                recommendations.append(f"  Score: {anomaly_info.get('anomaly_score', 0):.2f}")
                for reason in anomaly_info.get('reasons', [])[:2]:
                    recommendations.append(f"  - {reason}")
                recommendations.append("")
        return recommendations
    def generate_text_report(self, report: Dict, filename: str):
        """Generate human-readable text report"""
        try:
            with open(filename, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write(f"IoT SECURITY SCAN REPORT - {self.selected_interface}\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Scan Date: {report['scan_date']}\n")
                f.write(f"Interface: {report['interface_scanned']}\n")
                f.write(f"Total Devices Scanned: {report['total_devices']}\n")
                f.write(f"AI Features Enabled: {report.get('ai_enabled', False)}\n\n")
                summary = report['summary']
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 40 + "\n")
                total_vulns = summary['vulnerabilities']['total']
                if total_vulns > 0:
                    f.write(f"SECURITY ALERT: {total_vulns} vulnerabilities found!\n")
                    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                        count = summary['vulnerabilities']['by_severity'][severity]
                        if count > 0:
                            f.write(f"  {severity}: {count} vulnerabilities\n")
                else:
                    f.write("No vulnerabilities found. Good!\n")
                if report.get('ai_enabled'):
                    ai_summary = summary.get('ai_analysis', {})
                    if ai_summary.get('devices_classified', 0) > 0:
                        f.write(f"\nAI ANALYSIS:\n")
                        f.write(f"  Devices classified by AI: {ai_summary['devices_classified']}\n")
                        f.write(f"  Average confidence: {ai_summary['average_confidence']:.2f}\n")
                        f.write(f"  Anomalies detected: {ai_summary.get('anomalies_detected', 0)}\n")
                f.write(f"\nDevice Types Found:\n")
                for dev_type, count in summary['device_types'].items():
                    f.write(f"  {dev_type}: {count}\n")
                f.write("\n" + "=" * 80 + "\n")
                f.write("DETAILED DEVICE ANALYSIS\n")
                f.write("=" * 80 + "\n\n")
                for ip, device in report['devices'].items():
                    f.write(f"DEVICE: {ip}\n")
                    f.write("-" * 60 + "\n")
                    f.write(f"Type: {device.get('device_type', 'Unknown')}\n")
                    f.write(f"MAC: {device.get('mac', 'Unknown')}\n")
                    f.write(f"Vendor: {device.get('vendor', 'Unknown')}\n")
                    if 'ai_classification' in device:
                        ai_info = device['ai_classification']
                        f.write(f"AI Classification Confidence: {ai_info.get('confidence', 0):.2f}\n")
                    if 'anomaly_detection' in device:
                        anomaly = device['anomaly_detection']
                        if anomaly.get('is_anomalous'):
                            f.write(f"ANOMALY DETECTED! Score: {anomaly.get('anomaly_score', 0):.2f}\n")
                            for reason in anomaly.get('reasons', [])[:2]:
                                f.write(f"  Reason: {reason}\n")
                    ports = device.get('ports', [])
                    if ports:
                        f.write(f"Open TCP Ports:\n")
                        for port_info in ports:
                            port = port_info.get('port')
                            service = port_info.get('service', 'unknown')
                            product = port_info.get('product', '')
                            version = port_info.get('version', '')
                            f.write(f"  Port {port}: {service}")
                            if product:
                                f.write(f" ({product}")
                                if version:
                                    f.write(f" v{version}")
                                f.write(")")
                            f.write("\n")
                    enhanced = device.get('enhanced_scans', {})
                    udp_scan = enhanced.get('udp_scan', {})
                    if udp_scan.get('open_ports'):
                        f.write(f"UDP Services:\n")
                        for port, info in udp_scan['open_ports'].items():
                            f.write(f"  Port {port}: {info.get('protocol', 'Unknown')}\n")
                    if 'vulnerabilities' in device:
                        f.write(f"\nSECURITY ISSUES: {len(device['vulnerabilities'])} found\n")
                        for vuln in device['vulnerabilities'][:5]:  
                            severity = vuln.get('severity', 'Unknown')
                            f.write(f"  [{severity}] {vuln.get('title', 'Unknown')}\n")
                    else:
                        f.write(f"\nSECURITY: No vulnerabilities found\n")
                    f.write("\n")
                f.write("\n" + "=" * 80 + "\n")
                f.write("SECURITY RECOMMENDATIONS\n")
                f.write("=" * 80 + "\n\n")
                for rec in report['recommendations']:
                    f.write(f"{rec}\n")
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            print(f"Error generating text report: {e}")
    def print_summary(self):
        """Print summary to console"""
        if not self.results:
            print("\nNo devices found to report.")
            return
        try:
            print("\n" + "=" * 60)
            print(f"SCAN RESULTS SUMMARY - {self.selected_interface}")
            print("=" * 60)
            total = len(self.results)
            vulnerable = sum(1 for d in self.results.values() if 'vulnerabilities' in d)
            anomalous = sum(1 for d in self.results.values() 
                          if d.get('anomaly_detection', {}).get('is_anomalous', False))
            print(f"\nInterface: {self.selected_interface}")
            print(f"Devices Found: {total}")
            print(f"Vulnerable Devices: {vulnerable}")
            if self.ai_enabled:
                print(f"Anomalous Devices: {anomalous}")
            print("\nDevice Types:")
            print("-" * 40)
            types = {}
            for device in self.results.values():
                dev_type = device.get('device_type', 'Unknown')
                types[dev_type] = types.get(dev_type, 0) + 1
            for dev_type, count in types.items():
                print(f"  {dev_type}: {count}")
            print("\nVulnerabilities Found:")
            print("-" * 40)
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for device in self.results.values():
                for vuln in device.get('vulnerabilities', []):
                    severity = vuln.get('severity', 'MEDIUM').upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
            found_vulns = False
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity_counts[severity] > 0:
                    print(f"  {severity}: {severity_counts[severity]}")
                    found_vulns = True
            if not found_vulns:
                print("  No vulnerabilities found")
            if self.ai_enabled:
                print("\nAI Analysis:")
                print("-" * 40)
                ai_classified = sum(1 for d in self.results.values() if 'ai_classification' in d)
                if ai_classified > 0:
                    avg_confidence = sum(d.get('ai_classification', {}).get('confidence', 0) 
                                       for d in self.results.values() if 'ai_classification' in d) / ai_classified
                    print(f"  Devices classified: {ai_classified}")
                    print(f"  Average confidence: {avg_confidence:.2f}")
                    print(f"  Anomalies detected: {anomalous}")
                else:
                    print("  No AI classification performed")
            filename = f'iot_scan_{self.selected_interface.replace(" ", "_")}'
            print(f"\nReports saved to:")
            print(f"  {filename}.json (Detailed JSON)")
            print(f"  {filename}_summary.txt (Human readable)")
            print("  devices.json (Device inventory)")
            print("  iot_scanner.log (Scan logs)")
            if self.ai_enabled:
                print("  anomaly_history.json (Anomaly tracking)")
        except Exception as e:
            logger.error(f"Error printing summary: {e}")
            print(f"Error printing summary: {e}")
def main():
    """Main function with AI features"""
    try:
        print("\n" + "=" * 60)
        print("IoT Security Scanner v3.0 - AI Enhanced")
        print("=" * 60)
        print("Features: AI Classification | Anomaly Detection")
        print("          Network Discovery | Vulnerability Scanning")
        print("=" * 60)
        scan_mode = 1
        interface = None
        if len(sys.argv) > 1:
            for i, arg in enumerate(sys.argv[1:], 1):
                if arg in ['-h', '--help']:
                    print("\nUsage: python iot_scanner.py [mode] [interface]")
                    print("\nModes:")
                    print("  1 - Quick Scan (Passive + Common ports) [DEFAULT]")
                    print("  2 - Deep Scan (Active + All ports + UDP)")
                    print("  3 - Comprehensive (All methods + AI)")
                    print("\nInterface options:")
                    print("  list                 - Show available interfaces")
                    print("  Wi-Fi                - Scan Wi-Fi interface")
                    print("  VMware Network       - Scan VMware interface")
                    print("  eth0                 - Scan specific interface")
                    print("  <IP Address>         - Scan interface with specific IP")
                    print("\nAI Features:")
                    print("  --train-ai           - Train AI models")
                    print("  --no-ai              - Disable AI features")
                    print("\nExamples:")
                    print("  python iot_scanner.py                     # Interactive mode")
                    print("  python iot_scanner.py 2 Wi-Fi            # Deep scan on Wi-Fi")
                    print("  python iot_scanner.py 3 vmnet1           # Comprehensive on VMnet1")
                    print("  python iot_scanner.py --train-ai         # Train AI models")
                    print("  python iot_scanner.py --no-ai            # Disable AI features")
                    sys.exit(0)
                elif arg in ['1', '2', '3']:
                    scan_mode = int(arg)
                elif arg == 'list':
                    interface = 'list'
                elif arg == '--train-ai':
                    print("\nTraining AI models...")
                    try:
                        from iot_security.train_ai_model import main as train_main
                        train_main(['--all'])
                        print("AI models trained successfully!")
                    except ImportError as e:
                        print(f"Error: Could not import training module: {e}")
                        print("Make sure train_ai_model.py is in the iot_security directory")
                    sys.exit(0)
                elif arg == '--no-ai':
                    global AI_MODULES_AVAILABLE
                    AI_MODULES_AVAILABLE = False
                    print("AI features disabled by user")
                else:
                    interface = arg
        required_modules = ['scapy', 'psutil', 'requests']
        missing_modules = []
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        if missing_modules:
            print(f"\n Error: Missing required modules: {', '.join(missing_modules)}")
            print("Install with: pip install -r requirements.txt")
            sys.exit(1)
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['nmap', '--version'], capture_output=True, shell=True, text=True)
            else:
                result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                print("\n  Warning: Nmap not found or not in PATH")
                print("Some features will be limited.")
                print("Download from: https://nmap.org/download.html")
        except:
            print("\n  Warning: Nmap not found or not in PATH")
            print("Some features will be limited.")
            print("Download from: https://nmap.org/download.html")
        print(f"\nStarting scan (Mode: {scan_mode})...")
        if AI_MODULES_AVAILABLE:
            print("AI features: ENABLED")
        else:
            print("AI features: DISABLED")
        print("Check iot_scanner.log for detailed logs")
        scanner = IoTSecurityScanner()
        scanner.run_scan(scan_mode=scan_mode, interface_choice=interface)
    except KeyboardInterrupt:
        print("\n\n  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n Fatal error: {e}")
        print("Check iot_scanner.log for details")
        logger.error(f"Fatal error in main: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
if __name__ == "__main__":
    main()
