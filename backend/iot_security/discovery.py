"""
Network Discovery Module
Finds all devices on the network safely using ARP scanning
"""
import json
import logging
import socket
import subprocess
import platform
import warnings
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import ipaddress
import concurrent.futures
try:
    import scapy.all as scapy
    scapy.conf.verb = 0
except ImportError:
    scapy = None
try:
    from mac_vendor_lookup import MacLookup
except ImportError:
    MacLookup = None
try:
    import psutil
except ImportError:
    psutil = None
warnings.filterwarnings("ignore", category=DeprecationWarning)
logger = logging.getLogger(__name__)
class NetworkUtils:
    """Cross-platform network utilities using psutil"""
    @staticmethod
    def get_local_ipv4_addresses() -> List[Tuple[str, str]]:
        """Get all local IPv4 addresses"""
        interfaces = []
        if psutil is None:
            try:
                hostname = socket.gethostname()
                # gethostbyname_ex works on Windows/Linux usually
                _, _, ips = socket.gethostbyname_ex(hostname)
                for ip in ips:
                    if not ip.startswith('127.') and not ip.startswith('169.254.'):
                        interfaces.append(("unknown", ip))
                return interfaces
            except Exception as e:
                logger.error(f"Fallback IP detection failed: {e}")
                return []

        try:
            for iface, addrs in psutil.net_if_addrs().items():
                if iface.lower().startswith(('docker', 'br-', 'veth', 'virbr', 'tap', 'tun')):
                    continue
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        if (not ip.startswith('127.') and 
                            not ip.startswith('169.254.')):
                            interfaces.append((iface, ip))
            interfaces.sort(key=lambda x: x[0])
            return interfaces
        except Exception as e:
            logger.error(f"Error getting IPv4 addresses: {e}")
            return []
    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """Get default gateway IP address"""
        try:
            system = platform.system()
            if system == "Windows":
                result = subprocess.run(
                    ['route', 'print', '0.0.0.0'], 
                    capture_output=True, 
                    text=True,
                    shell=True,
                    stdin=subprocess.DEVNULL
                )
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and len(line.strip()) > 0:
                        parts = [p for p in line.split() if p]
                        if len(parts) > 2 and parts[0] == '0.0.0.0':
                            return parts[2]
            elif system == "Darwin":
                result = subprocess.run(
                    ['netstat', '-rn'], 
                    capture_output=True, 
                    text=True,
                    stdin=subprocess.DEVNULL
                )
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'default' in line.lower():
                        parts = [p for p in line.split() if p]
                        if len(parts) > 1:
                            return parts[1]
            else:
                result = subprocess.run(
                    ['ip', 'route', 'show', 'default'], 
                    capture_output=True, 
                    text=True,
                    stdin=subprocess.DEVNULL
                )
                if result.stdout:
                    parts = result.stdout.strip().split()
                    if len(parts) > 2:
                        return parts[2]
            return None
        except Exception as e:
            logger.error(f"Error getting default gateway: {e}")
            return None
    @staticmethod
    def get_network_info() -> Dict:
        """Get comprehensive network information"""
        info = {
            "interfaces": [],
            "default_gateway": None,
            "local_ips": []
        }
        if psutil is None:
             info["local_ips"] = NetworkUtils.get_local_ipv4_addresses()
             info["default_gateway"] = NetworkUtils.get_default_gateway()
             return info

        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for iface, addresses in addrs.items():
                if iface.lower().startswith(('docker', 'br-', 'veth', 'virbr', 'tap', 'tun')):
                    continue
                interface_info = {
                    "name": iface,
                    "is_up": stats[iface].isup if iface in stats else False,
                    "addresses": []
                }
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        family_name = "IPv4"
                    elif addr.family == socket.AF_INET6:
                        family_name = "IPv6"
                    elif hasattr(addr, 'family') and addr.family == -1:
                        family_name = "MAC"
                    else:
                        family_name = "Other"
                    addr_info = {
                        "family": family_name,
                        "address": addr.address
                    }
                    if hasattr(addr, 'netmask') and addr.netmask:
                        addr_info["netmask"] = addr.netmask
                    if hasattr(addr, 'broadcast') and addr.broadcast:
                        addr_info["broadcast"] = addr.broadcast
                    interface_info["addresses"].append(addr_info)
                info["interfaces"].append(interface_info)
            info["local_ips"] = NetworkUtils.get_local_ipv4_addresses()
            info["default_gateway"] = NetworkUtils.get_default_gateway()
            return info
        except Exception as e:
            logger.error(f"Error getting network info: {e}")
            return info
    @staticmethod
    def calculate_network_range(ip: str, netmask: str) -> Optional[str]:
        """Calculate network range from IP and netmask"""
        try:
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            network_parts = []
            for i in range(4):
                network_parts.append(str(ip_parts[i] & mask_parts[i]))
            network_ip = '.'.join(network_parts)
            binary_str = ''.join([bin(x)[2:].zfill(8) for x in mask_parts])
            cidr = binary_str.count('1')
            return f"{network_ip}/{cidr}"
        except Exception as e:
            logger.error(f"Error calculating network range: {e}")
            return None
    @staticmethod
    def ping_host(ip: str, timeout: int = 2) -> bool:
        """Ping a host to check if it's alive"""
        try:
            system = platform.system()
            if system == "Windows":
                param = "-n"
                timeout_param = "-w"
                timeout_ms = timeout * 1000
                command = ['ping', param, '1', timeout_param, str(timeout_ms), ip]
            else:
                param = "-c"
                timeout_param = "-W"
                command = ['ping', param, '1', timeout_param, str(timeout), ip]
            
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1,
                    stdin=subprocess.DEVNULL
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, OSError):
                return False
        except:
            return False
class NetworkDiscovery:
    """Discovers devices on local network using ARP scanning"""
    def __init__(self, output_file="devices.json"):
        self.output_file = output_file
        try:
            if MacLookup:
                self.mac_lookup = MacLookup()
            else:
                self.mac_lookup = None
        except Exception as e:
            logger.warning(f"MAC vendor lookup not available: {e}")
            self.mac_lookup = None
        self.discovered_devices = {}
        self.network_utils = NetworkUtils()
    def is_non_device_address(self, ip: str) -> bool:
        """Check if an IP is a non-device address (multicast, broadcast, etc.)"""
        if ip.startswith(("224.", "225.", "226.", "227.", "228.", "229.", 
                          "230.", "231.", "232.", "233.", "234.", "235.",
                          "236.", "237.", "238.", "239.")):
            return True
        if ip == "255.255.255.255":
            return True
        if ip.endswith(".255"):
            try:
                parts = list(map(int, ip.split('.')))
                if len(parts) == 4 and parts[3] == 255:
                    return True
            except:
                pass
        if ip.startswith("169.254."):
            return True
        if ip.startswith("127."):
            return True
        if ip.endswith(".0"):
            try:
                parts = list(map(int, ip.split('.')))
                if len(parts) == 4 and parts[3] == 0:
                    return True
            except:
                pass
        return False
    def filter_by_subnet(self, devices: Dict[str, Dict], network_cidr: str, extra_subnets: List[str] = None) -> Dict[str, Dict]:
        """Filter devices to only include IPs in the specified subnet(s)"""
        filtered_devices = {}
        allowed_prefixes = []
        
        try:
            # Helper to get prefix from CIDR
            def get_prefix(cidr):
                if not cidr: return None
                if '/' in cidr:
                    network_ip = cidr.split('/')[0]
                    return network_ip.rsplit('.', 1)[0] + "."
                else:
                    return cidr.rsplit('.', 1)[0] + "."

            if network_cidr:
                prefix = get_prefix(network_cidr)
                if prefix: allowed_prefixes.append(prefix)
            
            if extra_subnets:
                for subnet in extra_subnets:
                    prefix = get_prefix(subnet)
                    if prefix: allowed_prefixes.append(prefix)
            
            for ip, device_info in devices.items():
                if self.is_non_device_address(ip):
                    logger.debug(f"Filtered out non-device address: {ip}")
                    continue
                
                # If no subnets specified, don't filter (or filter aggressively? safely assume keep local)
                if not allowed_prefixes:
                    filtered_devices[ip] = device_info
                    continue

                matched = False
                for prefix in allowed_prefixes:
                    if ip.startswith(prefix):
                        matched = True
                        break
                
                if matched:
                    filtered_devices[ip] = device_info
                else:
                    logger.debug(f"Filtered out {ip} - not in allowed networks {allowed_prefixes}")
                    
        except Exception as e:
            logger.error(f"Error filtering by subnet: {e}")
            for ip, device_info in devices.items():
                if not self.is_non_device_address(ip):
                    filtered_devices[ip] = device_info
        return filtered_devices
    def get_local_network_range(self) -> Optional[str]:
        """Get local network range in CIDR notation"""
        try:
            local_ips = self.network_utils.get_local_ipv4_addresses()
            if not local_ips:
                logger.warning("No local IPv4 addresses found")
                return "192.168.1.0/24"
            for iface, ip in local_ips:
                # if 'vmware' in iface.lower() or 'virtual' in iface.lower():
                #     continue
                logger.info(f"Primary interface: {iface}, IP: {ip}")
                info = self.network_utils.get_network_info()
                for interface in info["interfaces"]:
                    if interface["name"] == iface:
                        for addr in interface.get("addresses", []):
                            if addr.get("family") == "IPv4" and "netmask" in addr:
                                netmask = addr["netmask"]
                                network_range = self.network_utils.calculate_network_range(ip, netmask)
                                if network_range:
                                    logger.info(f"Detected network range: {network_range}")
                                    return network_range
            iface, ip = local_ips[0]
            logger.info(f"Using fallback interface: {iface}, IP: {ip}")
            if ip.startswith("192.168."):
                network = f"{ip.rsplit('.', 1)[0]}.0/24"
                logger.info(f"Fallback network range: {network}")
                return network
            elif ip.startswith("10."):
                logger.info("Fallback network range: 10.0.0.0/8")
                return "10.0.0.0/8"
            elif ip.startswith("172."):
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    network = f"172.{second_octet}.0.0/16"
                    logger.info(f"Fallback network range: {network}")
                    return network
            logger.warning("Using default network range: 192.168.1.0/24")
            return "192.168.1.0/24"
        except Exception as e:
            logger.error(f"Error getting network range: {e}")
            return "192.168.1.0/24"
    def get_local_ip(self) -> Optional[str]:
        """Get local IP address"""
        local_ips = self.network_utils.get_local_ipv4_addresses()
        return local_ips[0][1] if local_ips else None
    def passive_arp_listen(self, timeout: int = 30) -> Dict[str, Dict]:
        """Listen for ARP packets to discover devices passively"""
        if scapy is None:
            logger.warning("Scapy not available. Passive ARP listening disabled.")
            return {}
        devices = {}
        def arp_callback(packet):
            try:
                if packet.haslayer(scapy.ARP):
                    arp_layer = packet[scapy.ARP]
                    if arp_layer.op == 1 or arp_layer.op == 2:
                        ip = arp_layer.psrc
                        mac = arp_layer.hwsrc
                        if ip == "0.0.0.0" or mac in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]:
                            return
                        if self.is_non_device_address(ip):
                            return
                        local_ip = self.get_local_ip()
                        if ip == local_ip:
                            return
                        vendor = "Unknown"
                        if self.mac_lookup:
                            try:
                                vendor = self.mac_lookup.lookup(mac)
                            except Exception:
                                pass
                        devices[ip] = {
                            "mac": mac,
                            "vendor": vendor,
                            "first_seen": datetime.now().isoformat(),
                            "last_seen": datetime.now().isoformat(),
                            "discovery_method": "passive_arp"
                        }
            except Exception as e:
                logger.debug(f"Error processing ARP packet: {e}")
        logger.info(f"Listening for ARP packets for {timeout} seconds...")
        try:
            scapy.sniff(filter="arp", prn=arp_callback, timeout=timeout, store=False, quiet=True)
        except PermissionError:
            logger.error("Permission denied. Try running with sudo/administrator privileges.")
            return {}
        except Exception as e:
            logger.error(f"Error during ARP listening: {e}")
            return {}
        logger.info(f"Passive discovery found {len(devices)} devices")
        return devices
    def ping_sweep(self, network_range: str) -> List[str]:
        """Perform a ping sweep to find active hosts"""
        active_hosts = []
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            
            # Safety check for large networks
            if network.num_addresses > 512:
                logger.warning(f"Network {network_range} is too large for ping sweep ({network.num_addresses} hosts). Limiting to /24.")
                
                # Logic duplicated from active_arp_scan for consistency
                # Attempt to refine the range to a manageable /24
                local_ip = self.get_local_ip()
                new_range = None
                
                if local_ip:
                    try:
                        local_addr = ipaddress.ip_address(local_ip)
                        if local_addr in network:
                            iface = ipaddress.ip_interface(f"{local_ip}/24")
                            new_range = str(iface.network)
                    except ValueError:
                        pass
                
                if not new_range:
                    try:
                        if network.prefixlen < 24:
                            subnets = network.subnets(new_prefix=24)
                            new_range = str(next(subnets))
                    except Exception:
                        pass
                
                if new_range:
                    network_range = new_range
                    # Re-initialize network object with new range for the loop below
                    network = ipaddress.ip_network(network_range, strict=False)
                else:
                    return []

            ips = [str(ip) for ip in network.hosts()]
            
            logger.info(f"Starting ping sweep for {len(ips)} hosts in {network_range}...")
            
            # Using ThreadPoolExecutor for parallel pinging
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=50)
            try:
                # ping_host is static method of NetworkUtils, but we have instance in self.network_utils
                future_to_ip = {executor.submit(self.network_utils.ping_host, ip, 1): ip for ip in ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            active_hosts.append(ip)
                    except Exception as exc:
                        logger.debug(f"Ping generated an exception for {ip}: {exc}")
                executor.shutdown(wait=True)
            except KeyboardInterrupt:
                logger.warning("Ping sweep interrupted by user")
                executor.shutdown(wait=False)
                raise
            except Exception as e:
                logger.error(f"Error in ping sweep execution: {e}")
                executor.shutdown(wait=False)
                        
            logger.info(f"Ping sweep found {len(active_hosts)} active hosts")
        except Exception as e:
            logger.error(f"Error during ping sweep: {e}")
            
        return active_hosts

    def discover_ssdp(self, timeout: int = 2) -> List[Dict]:
        """Discover devices using SSDP (Simple Service Discovery Protocol)"""
        devices = []
        ssdp_request = (
            'M-SEARCH * HTTP/1.1\r\n'
            'HOST: 239.255.255.250:1900\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 1\r\n'
            'ST: ssdp:all\r\n'
            '\r\n'
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.bind(('', 0)) # Bind to ephemeral port
            
            # Send to multicast group
            sock.sendto(ssdp_request.encode(), ('239.255.255.250', 1900))
            
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    ip = addr[0]
                    response = data.decode('utf-8', errors='ignore')
                    
                    # Extract info from headers
                    headers = {}
                    for line in response.split('\r\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.upper()] = value.strip()
                            
                    server = headers.get('SERVER', 'Unknown')
                    location = headers.get('LOCATION', '')
                    usn = headers.get('USN', '')
                    
                    devices.append({
                        'ip': ip,
                        'server': server,
                        'location': location,
                        'usn': usn,
                        'discovery_method': 'ssdp'
                    })
                except socket.timeout:
                    break
                except Exception:
                    continue
            sock.close()
        except Exception as e:
            logger.debug(f"SSDP discovery error: {e}")
            
        return devices

    def active_arp_scan(self, network_range: str = None) -> Dict[str, Dict]:
        """Perform active ARP scan and Ping sweep of network"""
        if scapy is None:
             logger.warning("Scapy not available. Using system ARP scan.")
             # System ARP scan needs to be called with a fallback logic or just rely on ping sweep + arp -a
             # But active_arp_scan does both ARP + Ping Sweep.
             # We should probably do ping sweep here then check ARP table.
             # Let's delegate to system_arp_scan entirely or emulate it.
             # Actually system_arp_scan just reads ARP table. It doesn't ping.
             # So we should run ping sweep first, then read ARP table.
             
             # Run ping sweep to populate ARP table
             if not network_range:
                 network_range = self.get_local_network_range()
             
             logger.info(f"Scapy missing. Running ping sweep on {network_range} to populate ARP table...")
             self.ping_sweep(network_range)
             
             # Then read system ARP table
             return self.system_arp_scan()

        if not network_range:
            network_range = self.get_local_network_range()
        logger.info(f"Active scanning network: {network_range}")
        devices = {}
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', network_range):
            logger.error(f"Invalid network range format: {network_range}")
            return devices
            
        # Check network size
        try:
            network = ipaddress.ip_network(network_range, strict=False)
            if network.num_addresses > 512:
                logger.warning(f"Network {network_range} too large for active ARP ({network.num_addresses} hosts). Limiting to /24.")
                
                # Attempt to refine the range to a manageable /24
                # First, check if our local IP is in this range, if so, scan that neighborhood
                local_ip = self.get_local_ip()
                new_range = None
                
                if local_ip:
                    try:
                        local_addr = ipaddress.ip_address(local_ip)
                        if local_addr in network:
                            # Create a /24 network containing the local IP
                            # This ensures we scan the segment we are actually on
                            # ipaddress interface logic handles the masking
                            # We construct a network from the IP with /24 mask
                            # But strictly, we want the network address. 
                            # ip_interface("1.2.3.4/24").network gives 1.2.3.0/24
                            iface = ipaddress.ip_interface(f"{local_ip}/24")
                            new_range = str(iface.network)
                            logger.info(f"Refined scan target to local subnet: {new_range}")
                    except ValueError:
                        pass
                
                if not new_range:
                    # Fallback: Just take the first /24 of the network
                    # This covers 10.0.0.0/8 -> 10.0.0.0/24 which usually has the gateway
                    try:
                        # Get the first subnet of size /24
                        # Calculate required prefix length change
                        if network.prefixlen < 24:
                            # Use the first /24 subnet
                            subnets = network.subnets(new_prefix=24)
                            new_range = str(next(subnets))
                            logger.info(f"Refined scan target to first subnet: {new_range}")
                    except Exception as e:
                        logger.warning(f"Could not calculate subnet: {e}")
                
                if new_range:
                    network_range = new_range
                else:
                    # If all else fails, return empty to avoid hang
                    logger.warning("Could not refine large network range. Skipping.")
                    return devices

        except Exception as e:
            logger.error(f"Error checking network size: {e}")
            pass

        try:
            logger.debug(f"Constructing ARP packet for {network_range}")
            arp_request = scapy.ARP(pdst=network_range)
            ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_packet = ether_frame / arp_request
            
            logger.debug("Sending ARP packets...")
            answered_list, _ = scapy.srp(
                arp_packet, 
                timeout=3, 
                verbose=False,
                retry=1
            )
            logger.info(f"ARP scan sent, received {len(answered_list)} responses")
            
            for sent, received in answered_list:
                ip = received.psrc
                mac = received.hwsrc
                logger.debug(f"ARP response: {ip} -> {mac}")
                
                if ip == "0.0.0.0" or mac in ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"]:
                    continue
                if self.is_non_device_address(ip):
                    logger.debug(f"Ignoring non-device address: {ip}")
                    continue
                local_ip = self.get_local_ip()
                if ip == local_ip:
                    logger.debug(f"Ignoring local IP: {ip}")
                    continue
                vendor = "Unknown"
                if self.mac_lookup:
                    try:
                        vendor = self.mac_lookup.lookup(mac)
                    except Exception:
                        pass
                devices[ip] = {
                    "mac": mac,
                    "vendor": vendor,
                    "first_seen": datetime.now().isoformat(),
                    "last_seen": datetime.now().isoformat(),
                    "discovery_method": "active_arp"
                }
            
            logger.info(f"Active ARP scan found {len(devices)} devices")
            
            # Perform Ping Sweep to find devices that didn't respond to ARP
            ping_hosts = self.ping_sweep(network_range)
            for ip in ping_hosts:
                if ip not in devices:
                    if self.is_non_device_address(ip):
                        continue
                    local_ip = self.get_local_ip()
                    if ip == local_ip:
                        continue
                        
                    logger.info(f"Found device via ping (no ARP response): {ip}")
                    devices[ip] = {
                        "mac": "Unknown",
                        "vendor": "Unknown",
                        "first_seen": datetime.now().isoformat(),
                        "last_seen": datetime.now().isoformat(),
                        "discovery_method": "ping_sweep"
                    }
                    
            # Perform SSDP Discovery for IoT devices
            ssdp_devices = self.discover_ssdp(timeout=2)
            for dev in ssdp_devices:
                ip = dev['ip']
                if ip not in devices:
                    if self.is_non_device_address(ip):
                        continue
                    local_ip = self.get_local_ip()
                    if ip == local_ip:
                        continue
                        
                    logger.info(f"Found device via SSDP: {ip} ({dev.get('server', 'Unknown')})")
                    devices[ip] = {
                        "mac": "Unknown",
                        "vendor": "Unknown", # Could infer from Server header potentially
                        "first_seen": datetime.now().isoformat(),
                        "last_seen": datetime.now().isoformat(),
                        "discovery_method": "ssdp",
                        "ssdp_info": dev
                    }
                else:
                    # Enrich existing device with SSDP info
                    devices[ip]['ssdp_info'] = dev
                    if devices[ip].get('discovery_method') == 'ping_sweep':
                         devices[ip]['discovery_method'] = 'ssdp_enhanced'

        except PermissionError:
            logger.error("Permission denied. Try running with sudo/administrator privileges.")
            return {}
        except Exception as e:
            logger.error(f"Error during active scan: {e}")
            devices = self.system_arp_scan()
            
        return devices
    def system_arp_scan(self, interface_name: str = None) -> Dict[str, Dict]:
        """Use system ARP command as fallback, optionally filtered by interface"""
        devices = {}
        try:
            system = platform.system()
            if system == "Windows":
                result = subprocess.run(
                    ['arp', '-a'],
                    capture_output=True,
                    text=True,
                    shell=True
                )
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and len(line.split()) >= 2:
                        parts = line.split()
                        if len(parts) >= 2 and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[0]):
                            ip = parts[0]
                            mac = parts[1]
                            if self.is_non_device_address(ip):
                                continue
                            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                                vendor = "Unknown"
                                if self.mac_lookup:
                                    try:
                                        vendor = self.mac_lookup.lookup(mac)
                                    except Exception:
                                        pass
                                devices[ip] = {
                                    "mac": mac,
                                    "vendor": vendor,
                                    "first_seen": datetime.now().isoformat(),
                                    "last_seen": datetime.now().isoformat(),
                                    "discovery_method": "system_arp"
                                }
            elif system in ["Linux", "Darwin"]:
                result = subprocess.run(
                    ['arp', '-n'],
                    capture_output=True,
                    text=True
                )
                lines = result.stdout.split('\n')
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[2]
                        if self.is_non_device_address(ip):
                            continue
                        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac):
                            vendor = "Unknown"
                            if self.mac_lookup:
                                try:
                                    vendor = self.mac_lookup.lookup(mac)
                                except Exception:
                                    pass
                            devices[ip] = {
                                "mac": mac,
                                "vendor": vendor,
                                "first_seen": datetime.now().isoformat(),
                                "last_seen": datetime.now().isoformat(),
                                "discovery_method": "system_arp"
                            }
            if interface_name and devices:
                network_range = self.get_network_range_for_interface(interface_name)
                if network_range:
                    devices = self.filter_by_subnet(devices, network_range)
            logger.info(f"System ARP scan found {len(devices)} devices")
        except Exception as e:
            logger.error(f"System ARP scan failed: {e}")
        return devices
    def nmap_ping_scan(self, subnets: List[str]) -> Dict[str, Dict]:
        """Perform Nmap ping scan on specified subnets"""
        devices = {}
        if not subnets:
            return devices
            
        logger.info(f"Starting Nmap ping scan on: {subnets}")
        try:
            # Join subnets for nmap command
            target_spec = " ".join(subnets)
            # Use -sn for ping scan (no port scan), -n to skip DNS resolution
            command = ['nmap', '-sn', '-n', target_spec]
            
            # If subnets are passed as list, we might need to iterate or pass as multiple args
            # subprocess expects list of args.
            # If target_spec has spaces, we should split it or extend command.
            # But nmap handles multiple targets.
            # Safer to extend command with the list
            command = ['nmap', '-sn', '-n'] + subnets
            
            logger.debug(f"Running nmap command: {command}")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120  # 2 mins timeout
            )
            
            if result.returncode == 0:
                current_ip = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('Nmap scan report for'):
                        parts = line.split()
                        # Format: Nmap scan report for 10.142.138.117
                        # Or: Nmap scan report for 10.142.138.117 (host.name)
                        if len(parts) >= 5:
                            # Usually the IP is the last part or in parenthesis
                            # But with -n (no DNS), it's just the IP at the end usually
                            # Example: Nmap scan report for 10.142.138.117
                            current_ip = parts[-1].strip('()')
                            
                    elif current_ip and 'MAC Address:' in line:
                        parts = line.split('MAC Address:')
                        if len(parts) > 1:
                            mac_part = parts[1].strip()
                            mac_parts = mac_part.split()
                            if len(mac_parts) > 0:
                                mac = mac_parts[0]
                                vendor = ' '.join(mac_parts[1:]) if len(mac_parts) > 1 else 'Unknown'
                                if self.is_non_device_address(current_ip):
                                    continue
                                devices[current_ip] = {
                                    'mac': mac,
                                    'vendor': vendor,
                                    'first_seen': datetime.now().isoformat(),
                                    'last_seen': datetime.now().isoformat(),
                                    'discovery_method': 'nmap_ping'
                                }
                                # Don't reset current_ip yet, might be more info? No, for ping scan usually done.
                                # But let's keep it until next 'Nmap scan report' or 'Host is up'
                    
                    elif current_ip and 'Host is up' in line:
                        # If we haven't seen MAC yet (e.g. routed subnet), we might still want to add it
                        if current_ip not in devices and not self.is_non_device_address(current_ip):
                            # Routed devices often won't show MAC in Nmap output if they are not on local subnet
                            devices[current_ip] = {
                                'mac': 'Unknown',
                                'vendor': 'Unknown',
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                                'discovery_method': 'nmap_ping_routed'
                            }
            else:
                logger.error(f"Nmap ping scan failed with code {result.returncode}: {result.stderr}")

        except Exception as e:
            logger.error(f"Error during Nmap ping scan: {e}")
            
        logger.info(f"Nmap ping scan found {len(devices)} devices")
        return devices

    def discover_devices(self, prefer_passive: bool = True, extra_subnets: List[str] = None) -> Dict[str, Dict]:
        """Main discovery method combining multiple techniques"""
        devices = {}
        local_ip = self.get_local_ip()
        network_range = self.get_local_network_range()
        logger.info(f"Starting network discovery")
        logger.debug(f"Discovery parameters: prefer_passive={prefer_passive}, extra_subnets={extra_subnets}")
        logger.info(f"Local IP: {local_ip}")
        logger.info(f"Network range: {network_range}")
        
        # 1. ARP Discovery (Local Subnet)
        if prefer_passive:
            logger.debug("Starting passive ARP listening...")
            passive_devices = self.passive_arp_listen(timeout=60)
            devices.update(passive_devices)
            logger.info(f"Passive discovery complete: {len(passive_devices)} devices")
            logger.debug(f"Passive devices found: {list(passive_devices.keys())}")

        if len(devices) < 5:
            logger.info("Performing active ARP scan...")
            active_devices = self.active_arp_scan(network_range)
            logger.debug(f"Active scan found: {len(active_devices)} devices")
            for ip, info in active_devices.items():
                if ip not in devices:
                    devices[ip] = info
        
        # 2. Nmap Ping Scan (Routed Subnets)
        if extra_subnets:
            logger.info("Performing Nmap ping scan on extra subnets...")
            nmap_devices = self.nmap_ping_scan(extra_subnets)
            for ip, info in nmap_devices.items():
                if ip not in devices:
                    devices[ip] = info
                    logger.info(f"Added routed device: {ip}")

        if local_ip in devices:
            logger.info(f"Removing local IP {local_ip} from results")
            del devices[local_ip]
            
        # Filter (allows both local range AND extra subnets)
        devices = self.filter_by_subnet(devices, network_range, extra_subnets)
        
        self.update_device_inventory(devices)
        self.save_devices(devices)
        if devices:
            logger.info(f"Discovery complete: {len(devices)} devices found")
            for ip in devices:
                logger.info(f"  - {ip}")
        else:
            logger.warning("No devices found.")
        return devices
    def scan_specific_network(self, network_range: str) -> Dict[str, Dict]:
        """Scan a specific network range"""
        logger.info(f"Scanning specific network: {network_range}")
        devices = {}
        active_devices = self.active_arp_scan(network_range)
        devices.update(active_devices)
        if not devices:
            system_devices = self.system_arp_scan()
            devices.update(system_devices)
        devices = self.filter_by_subnet(devices, network_range)
        local_ip = self.get_local_ip()
        if local_ip in devices:
            del devices[local_ip]
        if devices:
            logger.info(f"Found {len(devices)} devices on {network_range}")
        else:
            logger.warning(f"No devices found on {network_range}")
        return devices
    def update_device_inventory(self, new_devices: Dict[str, Dict]):
        """Update device inventory with new discoveries"""
        try:
            with open(self.output_file, 'r') as f:
                existing_devices = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_devices = {}
        for ip, device_info in new_devices.items():
            if ip in existing_devices:
                existing_devices[ip]["last_seen"] = device_info["last_seen"]
            else:
                existing_devices[ip] = device_info
        self.discovered_devices = existing_devices
    def save_devices(self, devices: Dict[str, Dict]):
        """Save devices to JSON file"""
        try:
            payload = self.discovered_devices if isinstance(self.discovered_devices, dict) and self.discovered_devices else devices
            with open(self.output_file, 'w') as f:
                json.dump(payload, f, indent=2)
            logger.info(f"Saved {len(payload)} devices to {self.output_file}")
        except Exception as e:
            logger.error(f"Error saving devices: {e}")
    def get_device_inventory(self) -> Dict[str, Dict]:
        """Get current device inventory"""
        return self.discovered_devices
    def print_network_info(self):
        """Log detailed network information"""
        logger.info("Network Information:")
        logger.info("=" * 50)
        info = self.network_utils.get_network_info()
        logger.info(f"Default Gateway: {info.get('default_gateway', 'Not found')}")
        local_ips = info.get("local_ips", [])
        if local_ips:
            logger.info("Local IP Addresses:")
            for iface, ip in local_ips:
                logger.info(f"  {iface}: {ip}")
        logger.info("\nNetwork Interfaces:")
        for interface in info.get("interfaces", []):
            status = "UP" if interface.get("is_up") else "DOWN"
            logger.info(f"  {interface['name']} ({status}):")
            for addr in interface.get("addresses", []):
                if addr.get('family') == 'IPv4':
                    addr_str = f"    {addr.get('family')}: {addr.get('address')}"
                    if 'netmask' in addr:
                        addr_str += f" (Netmask: {addr['netmask']})"
                    logger.info(addr_str)
    def get_network_range_for_interface(self, interface_name: str) -> Optional[str]:
        """Get network range for specific interface"""
        try:
            local_ips = self.network_utils.get_local_ipv4_addresses()
            for iface, ip in local_ips:
                if iface == interface_name:
                    info = self.network_utils.get_network_info()
                    for interface in info["interfaces"]:
                        if interface["name"] == iface:
                            for addr in interface["addresses"]:
                                if addr.get("family") == "IPv4" and "netmask" in addr:
                                    netmask = addr["netmask"]
                                    network_range = self.network_utils.calculate_network_range(ip, netmask)
                                    return network_range
            return self.get_local_network_range()
        except Exception as e:
            logger.error(f"Error getting network range for {interface_name}: {e}")
            return None
    def discover_devices_on_interface(self, interface_name: str, prefer_passive: bool = True, extra_subnets: List[str] = None) -> Dict[str, Dict]:
        """Discover devices on specific network interface"""
        devices = {}
        try:
            network_range = self.get_network_range_for_interface(interface_name)
            logger.info(f"Scanning interface {interface_name}, network: {network_range}")
            active_devices = self.active_arp_scan(network_range)
            devices.update(active_devices)
            system_devices = self.system_arp_scan(interface_name)
            for ip, info in system_devices.items():
                if ip not in devices:
                    devices[ip] = info
            
            # Add Nmap ping scan for extra subnets if provided
            if extra_subnets:
                logger.info(f"Performing Nmap ping scan on extra subnets via {interface_name}...")
                nmap_devices = self.nmap_ping_scan(extra_subnets)
                for ip, info in nmap_devices.items():
                    if ip not in devices:
                        devices[ip] = info
            
            # Filter (allows both local range AND extra subnets)
            devices = self.filter_by_subnet(devices, network_range, extra_subnets)
            
            self.update_device_inventory(devices)
            self.save_devices(devices)
            logger.info(f"Found {len(devices)} devices on interface {interface_name}")
        except Exception as e:
            logger.error(f"Error scanning interface {interface_name}: {e}")
        return devices

    def comprehensive_scan_on_interface(self, interface_name: str, extra_subnets: List[str] = None) -> Dict[str, Dict]:
        """Comprehensive scan on specific interface"""
        devices = {}
        try:
            network_range = self.get_network_range_for_interface(interface_name)
            logger.info(f"Comprehensive scan on {interface_name}, network: {network_range}")
            logger.info("Phase 1: Active ARP scan...")
            active_devices = self.active_arp_scan(network_range)
            devices.update(active_devices)
            logger.info("Phase 2: System ARP scan...")
            system_devices = self.system_arp_scan(interface_name)
            for ip, info in system_devices.items():
                if ip not in devices:
                    devices[ip] = info
            
            # Phase 2.5: Nmap ping scan for extra subnets
            if extra_subnets:
                logger.info("Phase 2.5: Nmap ping scan on extra subnets...")
                nmap_devices = self.nmap_ping_scan(extra_subnets)
                for ip, info in nmap_devices.items():
                    if ip not in devices:
                        devices[ip] = info

            if len(devices) < 3:
                logger.info("Phase 3: Trying alternative subnets...")
                if network_range:
                    base_ip = network_range.split('/')[0]
                    if base_ip.startswith("192.168."):
                        for i in range(0, 10):
                            alt_network = f"192.168.{i}.0/24"
                            if alt_network != network_range:
                                alt_devices = self.active_arp_scan(alt_network)
                                for ip, info in alt_devices.items():
                                    if ip not in devices:
                                        devices[ip] = info
            
            # Filter (allows both local range AND extra subnets)
            devices = self.filter_by_subnet(devices, network_range, extra_subnets)
            
            self.update_device_inventory(devices)
            self.save_devices(devices)
            logger.info(f"Comprehensive scan found {len(devices)} devices on {interface_name}")
        except Exception as e:
            logger.error(f"Error in comprehensive scan on {interface_name}: {e}")
        return devices
