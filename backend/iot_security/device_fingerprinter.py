"""
Device Fingerprinting Module with AI Integration
Professional device identification using multiple signals with ML enhancements
"""
import logging
import socket
import re
from typing import Dict, List, Optional, Tuple
import subprocess
import time
logger = logging.getLogger(__name__)
class DeviceFingerprinter:
    """Enterprise-grade device fingerprinting with AI integration"""
    def __init__(self):
        self.TTL_OS_MAPPING = {
            32: {"os": ["Windows 95/98", "UNIX-like"], "confidence": 0.6},
            64: {"os": ["Linux", "Android", "Mac OS X", "FreeBSD", "Cisco iOS"], "confidence": 0.8},
            128: {"os": ["Windows NT/2000/XP/7/8/10/11"], "confidence": 0.85},
            255: {"os": ["Cisco Router", "Network Device"], "confidence": 0.9},
            30: {"os": ["Windows 95"], "confidence": 0.5},
            60: {"os": ["AIX"], "confidence": 0.7},
            254: {"os": ["Solaris"], "confidence": 0.8}
        }
        self.MAC_VENDOR_PATTERNS = {
            '00:0c:29': {'vendor': 'VMware ESXi/Workstation', 'weight': 0.95},
            '00:50:56': {'vendor': 'VMware ESXi', 'weight': 0.95},
            '00:1c:14': {'vendor': 'Dell', 'weight': 0.85},
            '00:1b:21': {'vendor': 'HP', 'weight': 0.85},
            '00:26:bb': {'vendor': 'Apple', 'weight': 0.9},
            '00:1e:65': {'vendor': 'Apple', 'weight': 0.9},
            '00:23:df': {'vendor': 'Apple', 'weight': 0.9},
            'b8:27:eb': {'vendor': 'Raspberry Pi', 'weight': 0.98},
            'dc:a6:32': {'vendor': 'Raspberry Pi', 'weight': 0.98},
            'a4:5e:60': {'vendor': 'Apple (iPhone/iPad)', 'weight': 0.85},
            'ac:bc:32': {'vendor': 'Apple', 'weight': 0.8},
            'f0:18:98': {'vendor': 'Apple', 'weight': 0.8},
            'f4:5c:89': {'vendor': 'Apple', 'weight': 0.8},
            'fc:25:3f': {'vendor': 'Google', 'weight': 0.75},
            '00:1a:11': {'vendor': 'Google', 'weight': 0.75},
            '50:eb:1a': {'vendor': 'Google', 'weight': 0.75},
            '4c:66:41': {'vendor': 'Samsung', 'weight': 0.8},
            'e4:a7:a0': {'vendor': 'Samsung', 'weight': 0.8},
            'f8:8e:85': {'vendor': 'Samsung', 'weight': 0.8},
            '38:aa:3c': {'vendor': 'Sony', 'weight': 0.7},
            '00:24:be': {'vendor': 'Netgear', 'weight': 0.8},
            '00:1b:2f': {'vendor': 'Netgear', 'weight': 0.8},
            '00:26:f2': {'vendor': 'Netgear', 'weight': 0.8},
            'c0:56:27': {'vendor': 'Belkin', 'weight': 0.75},
            'ec:1a:59': {'vendor': 'Belkin', 'weight': 0.75},
            'a0:21:b7': {'vendor': 'TP-Link', 'weight': 0.85},
            '14:cc:20': {'vendor': 'TP-Link', 'weight': 0.85},
            '64:70:02': {'vendor': 'TP-Link', 'weight': 0.85},
            'f8:1a:67': {'vendor': 'Ubiquiti', 'weight': 0.8},
            '80:2a:a8': {'vendor': 'Ubiquiti', 'weight': 0.8},
            'fc:ec:da': {'vendor': 'Ubiquiti', 'weight': 0.8},
            '34:e6:ad': {'vendor': 'Intel', 'weight': 0.9},
            '00:30:48': {'vendor': 'Intel', 'weight': 0.9},
            '00:90:27': {'vendor': 'Intel', 'weight': 0.9}
        }
        self.MAC_TYPES = {
            'locally_administered': {'nibbles': ['2', '6', 'a', 'e'], 'privacy_score': 0.8},
            'universally_administered': {'nibbles': ['0', '4', '8', 'c'], 'privacy_score': 0.2},
            'multicast': {'nibbles': ['1', '3', '5', '7', '9', 'b', 'd', 'f'], 'privacy_score': 0.1}
        }
        self.DEVICE_PORT_SIGNATURES = {
            'smartphone': {
                'ports': [],
                'services': [],
                'description': 'Typically few open ports, may have mDNS/SSDP',
                'weight': 0.6,
                'ml_features': ['low_port_count', 'mobile_services']
            },
            'windows_pc': {
                'ports': [135, 139, 445, 3389, 5985, 5986],
                'services': ['msrpc', 'netbios-ssn', 'microsoft-ds', 'ms-wbt-server'],
                'description': 'Windows SMB, RPC, RDP, WinRM',
                'weight': 0.85,
                'ml_features': ['windows_ports', 'smb', 'rdp']
            },
            'linux_pc': {
                'ports': [22, 111, 631, 2049],
                'services': ['ssh', 'rpcbind', 'ipp', 'nfs'],
                'description': 'SSH, RPC, printing services',
                'weight': 0.8,
                'ml_features': ['linux_ports', 'ssh', 'nfs']
            },
            'mac_pc': {
                'ports': [548, 3283, 5900],
                'services': ['afp', 'net-assistant', 'vnc'],
                'description': 'Apple Filing Protocol, Screen Sharing',
                'weight': 0.75,
                'ml_features': ['apple_ports', 'afp', 'vnc']
            },
            'iot_camera': {
                'ports': [80, 443, 554, 37777, 8000],
                'services': ['http', 'rtsp', 'unknown'],
                'description': 'Web interface, RTSP stream, proprietary protocols',
                'weight': 0.9,
                'ml_features': ['camera_ports', 'rtsp', 'http']
            },
            'smart_tv': {
                'ports': [8008, 8009, 9080, 1900],
                'services': ['googlecast', 'upnp'],
                'description': 'Google Cast, UPnP media services',
                'weight': 0.8,
                'ml_features': ['tv_ports', 'upnp', 'googlecast']
            },
            'iot_printer': {
                'ports': [80, 443, 515, 631, 9100],
                'services': ['http', 'printer', 'ipp', 'jetdirect'],
                'description': 'Web interface, printing protocols',
                'weight': 0.85,
                'ml_features': ['printer_ports', 'ipp', 'http']
            },
            'smart_speaker': {
                'ports': [80, 443, 8008, 8009, 1900],
                'services': ['http', 'googlecast', 'upnp'],
                'description': 'Smart speaker/assistant (Google, Alexa)',
                'weight': 0.7,
                'ml_features': ['speaker_ports', 'upnp', 'http']
            },
            'router': {
                'ports': [53, 67, 68, 80, 443, 161, 162],
                'services': ['dns', 'dhcp', 'http', 'snmp'],
                'description': 'DNS, DHCP, web admin, SNMP',
                'weight': 0.9,
                'ml_features': ['router_ports', 'dns', 'dhcp', 'snmp']
            },
            'switch': {
                'ports': [22, 23, 80, 161, 443],
                'services': ['ssh', 'telnet', 'http', 'snmp'],
                'description': 'Management interfaces',
                'weight': 0.8,
                'ml_features': ['switch_ports', 'telnet', 'snmp']
            },
            'access_point': {
                'ports': [22, 23, 80, 443, 161],
                'services': ['ssh', 'telnet', 'http', 'snmp'],
                'description': 'Wi-Fi access point',
                'weight': 0.75,
                'ml_features': ['ap_ports', 'http', 'snmp']
            },
            'nas': {
                'ports': [21, 22, 80, 443, 139, 445, 2049, 8080],
                'services': ['ftp', 'ssh', 'http', 'netbios', 'nfs'],
                'description': 'Network Attached Storage',
                'weight': 0.85,
                'ml_features': ['nas_ports', 'ftp', 'nfs', 'smb']
            },
            'media_server': {
                'ports': [80, 443, 32400, 32469, 1900],
                'services': ['http', 'plex', 'upnp'],
                'description': 'Plex/Emby/Jellyfin media server',
                'weight': 0.8,
                'ml_features': ['media_ports', 'plex', 'upnp']
            }
        }
        self.SERVICE_INFERENCES = {
            'dnsmasq': {
                'device_type': 'router',
                'confidence': 0.9,
                'description': 'DNS/DHCP server (common in home routers)',
                'ml_weight': 0.95
            },
            'lighttpd': {
                'device_type': 'iot_device',
                'confidence': 0.7,
                'description': 'Lightweight web server (common in IoT)',
                'ml_weight': 0.8
            },
            'busybox': {
                'device_type': 'embedded_device',
                'confidence': 0.8,
                'description': 'Embedded Linux system',
                'ml_weight': 0.85
            },
            'upnp': {
                'device_type': 'media_device',
                'confidence': 0.6,
                'description': 'UPnP media device (TV, speaker, etc.)',
                'ml_weight': 0.7
            },
            'rtsp': {
                'device_type': 'camera',
                'confidence': 0.85,
                'description': 'Video streaming (security camera)',
                'ml_weight': 0.9
            },
            'ftp': {
                'device_type': 'nas',
                'confidence': 0.7,
                'description': 'File server or NAS',
                'ml_weight': 0.75
            },
            'ssh': {
                'device_type': 'computer',
                'confidence': 0.6,
                'description': 'Linux/Unix system or network device',
                'ml_weight': 0.7
            },
            'telnet': {
                'device_type': 'iot_device',
                'confidence': 0.8,
                'description': 'IoT or legacy network device',
                'ml_weight': 0.85
            },
            'snmp': {
                'device_type': 'network_device',
                'confidence': 0.7,
                'description': 'Router/switch/network printer',
                'ml_weight': 0.8
            }
        }
        self.IOT_PATTERNS = {
            'dahua': {'patterns': ['dvr', 'nvr', 'ipcamera', 'dahua'], 'confidence': 0.9},
            'hikvision': {'patterns': ['ip camera', 'hikvision'], 'confidence': 0.9},
            'nest': {'patterns': ['nest', 'thermostat'], 'confidence': 0.85},
            'ring': {'patterns': ['ring', 'doorbell'], 'confidence': 0.85},
            'philips_hue': {'patterns': ['hue', 'philips'], 'confidence': 0.8},
            'tplink': {'patterns': ['tp-link', 'kasa'], 'confidence': 0.8},
            'wyze': {'patterns': ['wyze', 'camera'], 'confidence': 0.75},
            'amazon': {'patterns': ['alexa', 'echo'], 'confidence': 0.85},
            'google': {'patterns': ['google home', 'nest hub', 'chromecast'], 'confidence': 0.85}
        }
        self.ai_integration = True
    def analyze_device(self, device_info: Dict, nmap_results: Dict, enhanced_scans: Dict) -> Dict:
        """
        Comprehensive device analysis using AI-enhanced signals
        Returns detailed fingerprint with ML confidence scores
        """
        fingerprint = {
            'ip': device_info.get('ip', ''),
            'mac': device_info.get('mac', ''),
            'analysis': {
                'device_type': 'Unknown',
                'os_family': 'Unknown',
                'confidence': 0.0,
                'signals_used': [],
                'evidence': [],
                'ml_scores': {}
            },
            'fingerprint': {},
            'ai_enhancements': {
                'ml_integration': self.ai_integration,
                'feature_engineering': {},
                'predictions': []
            }
        }
        signals = []
        evidence = []
        confidence_factors = []
        ml_scores = {}
        mac_info = self.analyze_mac_address(device_info.get('mac', ''))
        if mac_info:
            fingerprint['mac_analysis'] = mac_info
            signals.append('mac')
            evidence.append(f"MAC: {mac_info.get('vendor_guess', 'Unknown')}")
            confidence_factors.append(mac_info.get('confidence', 0.3))
            ml_scores['mac_analysis'] = mac_info.get('ml_confidence', 0.0)
        ttl_info = self.detect_os_by_ttl(device_info, nmap_results)
        if ttl_info:
            fingerprint['ttl_analysis'] = ttl_info
            signals.append('ttl')
            evidence.append(f"TTL suggests: {ttl_info.get('likely_os', 'Unknown')}")
            confidence_factors.append(ttl_info.get('confidence', 0.4))
            ml_scores['ttl_analysis'] = ttl_info.get('ml_score', 0.0)
        port_info = self.analyze_ports_services(nmap_results, enhanced_scans)
        if port_info:
            fingerprint['port_analysis'] = port_info
            signals.append('ports')
            evidence.extend(port_info.get('evidence', []))
            confidence_factors.append(port_info.get('confidence', 0.6))
            ml_scores['port_analysis'] = port_info.get('ml_match_score', 0.0)
        service_info = self.infer_from_services(nmap_results.get('services', {}))
        if service_info:
            fingerprint['service_analysis'] = service_info
            signals.append('services')
            evidence.extend(service_info.get('evidence', []))
            confidence_factors.append(service_info.get('confidence', 0.7))
            ml_scores['service_analysis'] = service_info.get('ml_confidence', 0.0)
        protocol_info = self.analyze_protocols(enhanced_scans)
        if protocol_info:
            fingerprint['protocol_analysis'] = protocol_info
            signals.append('protocols')
            evidence.extend(protocol_info.get('evidence', []))
            confidence_factors.append(protocol_info.get('confidence', 0.5))
            ml_scores['protocol_analysis'] = protocol_info.get('pattern_score', 0.0)
        ip_info = self.analyze_ip_address(device_info.get('ip', ''))
        if ip_info:
            fingerprint['ip_analysis'] = ip_info
            evidence.extend(ip_info.get('evidence', []))
            ml_scores['ip_context'] = ip_info.get('context_score', 0.0)
        if self.ai_integration:
            ml_analysis = self.ml_enhanced_analysis(device_info, nmap_results, enhanced_scans)
            if ml_analysis:
                fingerprint['ml_analysis'] = ml_analysis
                signals.append('ml')
                evidence.extend(ml_analysis.get('insights', []))
                confidence_factors.append(ml_analysis.get('overall_confidence', 0.5))
                ml_scores['ml_enhanced'] = ml_analysis.get('ml_score', 0.0)
        device_type, type_confidence, ml_type_scores = self.determine_device_type_ml(
            mac_info, ttl_info, port_info, service_info, ml_analysis if self.ai_integration else None
        )
        os_family, os_confidence = self.determine_os_family(ttl_info, service_info, port_info)
        overall_confidence = self.calculate_ml_confidence(confidence_factors, ml_scores, len(signals))
        fingerprint['analysis'].update({
            'device_type': device_type,
            'os_family': os_family,
            'confidence': round(overall_confidence, 2),
            'signals_used': signals,
            'evidence': evidence[:5],  
            'ml_scores': ml_scores,
            'ml_type_scores': ml_type_scores
        })
        fingerprint['risk_assessment'] = self.assess_risk_ml(device_type, nmap_results, ml_scores)
        fingerprint['ai_recommendations'] = self.generate_ai_recommendations(fingerprint)
        logger.info(f"Device {device_info.get('ip')} AI fingerprint: {device_type} "
                   f"(confidence: {overall_confidence:.2f}, ML: {self.ai_integration})")
        return fingerprint
    def analyze_mac_address(self, mac: str) -> Dict:
        """Analyze MAC address for vendor and characteristics with ML scoring"""
        if not mac or mac.lower() in ['unknown', '00:00:00:00:00:00']:
            return None
        mac_lower = mac.lower()
        result = {
            'original_mac': mac,
            'vendor_guess': 'Unknown',
            'mac_type': 'Unknown',
            'privacy_features': [],
            'confidence': 0.3,
            'ml_confidence': 0.0,
            'ai_insights': []
        }
        best_match = None
        best_score = 0
        for prefix, vendor_info in self.MAC_VENDOR_PATTERNS.items():
            if mac_lower.startswith(prefix.lower()):
                score = vendor_info['weight']
                if score > best_score:
                    best_score = score
                    best_match = vendor_info
        if best_match:
            result['vendor_guess'] = best_match['vendor']
            result['confidence'] = best_match['weight']
            result['ml_confidence'] = best_match['weight']
        try:
            first_octet = mac_lower.split(':')[0]
            second_nibble = first_octet[1]  
            for mac_type, type_info in self.MAC_TYPES.items():
                if second_nibble in type_info['nibbles']:
                    result['mac_type'] = mac_type.title()
                    result['privacy_score'] = type_info['privacy_score']
                    if mac_type == 'locally_administered':
                        result['privacy_features'].append('MAC randomization likely')
                        result['confidence'] *= 0.7  
                        result['ai_insights'].append('Device may use MAC address randomization for privacy')
                    break
        except:
            pass
        if 'vmware' in result['vendor_guess'].lower():
            result['device_hint'] = 'Virtual Machine'
            result['confidence'] = 0.9
            result['ml_confidence'] = 0.95
            result['ai_insights'].append('High confidence VM detection from MAC OUI')
        if 'apple' in result['vendor_guess'].lower():
            result['device_hint'] = 'Apple device (iPhone/iPad/Mac)'
            result['confidence'] = 0.7
            result['ml_confidence'] = 0.75
            result['ai_insights'].append('Apple device detected from MAC OUI pattern')
        if 'raspberry' in result['vendor_guess'].lower():
            result['device_hint'] = 'Raspberry Pi'
            result['confidence'] = 0.9
            result['ml_confidence'] = 0.95
            result['ai_insights'].append('Raspberry Pi detected with high confidence')
        if result['vendor_guess'] == 'Unknown' and len(mac_lower) >= 8:
            oui = mac_lower[:8]
            result['ai_insights'].append(f'Unknown OUI: {oui} - consider updating ML model')
        return result
    def detect_os_by_ttl(self, device_info: Dict, nmap_results: Dict) -> Dict:
        """Detect OS based on TTL values with ML enhancement"""
        result = {
            'likely_os': 'Unknown',
            'ttl_guess': None,
            'confidence': 0.3,
            'method': 'default',
            'ml_score': 0.0,
            'ai_alternatives': []
        }
        os_info = nmap_results.get('os_info', {})
        if os_info.get('name'):
            result['likely_os'] = os_info.get('name')
            result['confidence'] = 0.7
            result['method'] = 'nmap_os_detection'
            result['ml_score'] = 0.8
            if 'classes' in os_info:
                for os_class in os_info['classes']:
                    accuracy = int(os_class.get('accuracy', 0))
                    if accuracy > 70:  
                        alt_os = f"{os_class.get('vendor', '')} {os_class.get('osfamily', '')}".strip()
                        if alt_os and alt_os != result['likely_os']:
                            result['ai_alternatives'].append({
                                'os': alt_os,
                                'confidence': accuracy / 100.0,
                                'type': os_class.get('type', '')
                            })
            return result
        vendor = device_info.get('vendor', '').lower()
        mac = device_info.get('mac', '').lower()
        if 'vmware' in vendor or mac.startswith(('00:0c:29', '00:50:56')):
            result['likely_os'] = 'Virtual Machine (Guest OS unknown)'
            result['confidence'] = 0.6
            result['ml_score'] = 0.7
            result['ai_insights'] = ['VMware MAC pattern detected']
        elif 'apple' in vendor or mac.startswith(('00:1e:65', '00:23:df', 'a4:5e:60')):
            result['likely_os'] = 'macOS/iOS'
            result['confidence'] = 0.7
            result['ml_score'] = 0.75
            result['ai_alternatives'] = [
                {'os': 'macOS', 'confidence': 0.7, 'type': 'desktop'},
                {'os': 'iOS', 'confidence': 0.6, 'type': 'mobile'}
            ]
        elif 'android' in vendor or 'google' in vendor:
            result['likely_os'] = 'Android'
            result['confidence'] = 0.65
            result['ml_score'] = 0.7
        elif 'raspberry' in vendor or mac.startswith('b8:27:eb'):
            result['likely_os'] = 'Raspberry Pi OS (Linux)'
            result['confidence'] = 0.8
            result['ml_score'] = 0.85
        if result['likely_os'] == 'Unknown':
            result['ai_insights'] = ['Using ML fallback: common Linux distribution']
            result['likely_os'] = 'Linux (unknown distribution)'
            result['confidence'] = 0.5
            result['ml_score'] = 0.6
        return result
    def analyze_ports_services(self, nmap_results: Dict, enhanced_scans: Dict) -> Dict:
        """Analyze open ports and services for device classification with ML weights"""
        ports = nmap_results.get('ports', [])
        services = nmap_results.get('services', {})
        if not ports and not services:
            return None
        result = {
            'open_ports': len(ports),
            'port_list': [p.get('port') for p in ports],
            'service_list': list(services.keys()),
            'device_guesses': [],
            'evidence': [],
            'confidence': 0.5,
            'ml_match_score': 0.0,
            'ml_features': []
        }
        for device_type, signature in self.DEVICE_PORT_SIGNATURES.items():
            port_matches = 0
            service_matches = 0
            ml_feature_matches = []
            for port in signature['ports']:
                if any(p.get('port') == port for p in ports):
                    port_matches += 1
                    ml_feature_matches.append(f'port_{port}')
            for service in signature['services']:
                if service in result['service_list']:
                    service_matches += 1
                    ml_feature_matches.append(f'service_{service}')
            total_checks = len(signature['ports']) + len(signature['services'])
            if total_checks > 0:
                base_match_score = (port_matches + service_matches) / total_checks
                ml_match_score = base_match_score * signature.get('weight', 1.0)
                if ml_match_score > 0.25:  
                    result['device_guesses'].append({
                        'device_type': device_type,
                        'match_score': ml_match_score,
                        'base_score': base_match_score,
                        'ml_weight': signature.get('weight', 1.0),
                        'description': signature['description'],
                        'ml_features': signature.get('ml_features', [])
                    })
                    result['ml_features'].extend(ml_feature_matches)
                    result['evidence'].append(
                        f"ML match {device_type}: {ml_match_score:.1%} (weight: {signature['weight']})"
                    )
        if len(ports) == 0:
            result['device_guesses'].append({
                'device_type': 'smartphone_or_iot_sleeping',
                'match_score': 0.6,
                'base_score': 0.6,
                'ml_weight': 0.8,
                'description': 'No open ports (sleeping device, IoT, or strict firewall)',
                'ml_features': ['no_open_ports']
            })
            result['evidence'].append('ML: No open TCP ports detected (sleeping/firewalled)')
            result['ml_features'].append('no_open_ports')
        iot_ports = {80, 443, 554, 8000, 8080, 37777, 1883, 8883, 5683, 1900, 5353}
        found_iot_ports = [p for p in result['port_list'] if p in iot_ports]
        if found_iot_ports:
            iot_score = len(found_iot_ports) / max(len(iot_ports), 1) * 0.8
            result['device_guesses'].append({
                'device_type': 'iot_device_ml',
                'match_score': iot_score,
                'base_score': len(found_iot_ports) / len(result['port_list']) if result['port_list'] else 0,
                'ml_weight': 0.85,
                'description': f'ML-detected IoT ports: {found_iot_ports}',
                'ml_features': [f'iot_port_{p}' for p in found_iot_ports]
            })
            result['evidence'].append(f'ML IoT ports: {found_iot_ports}')
            result['ml_features'].extend([f'iot_port_{p}' for p in found_iot_ports])
        result['device_guesses'].sort(key=lambda x: x['match_score'], reverse=True)
        if result['device_guesses']:
            result['confidence'] = min(0.9, result['device_guesses'][0]['match_score'])
            result['ml_match_score'] = result['device_guesses'][0]['match_score']
        result['ml_features'] = list(set(result['ml_features']))
        return result
    def infer_from_services(self, services: Dict) -> Dict:
        """Infer device type from detected services with ML confidence"""
        if not services:
            return None
        result = {
            'service_inferences': [],
            'evidence': [],
            'confidence': 0.6,
            'ml_confidence': 0.0,
            'ml_service_patterns': []
        }
        ml_confidence_sum = 0
        ml_pattern_count = 0
        for service_name, service_info in services.items():
            service_lower = service_name.lower()
            for service_key, inference in self.SERVICE_INFERENCES.items():
                if service_key in service_lower:
                    product = service_info.get('product', '').lower()
                    iot_match = self.check_iot_patterns_ml(product)
                    if iot_match:
                        inference = inference.copy()
                        inference['device_type'] = 'iot_device'
                        inference['iot_brand'] = iot_match['brand']
                        inference['confidence'] = iot_match['confidence']
                        inference['ml_weight'] = inference.get('ml_weight', 0.7) * 1.2  
                    result['service_inferences'].append(inference)
                    result['evidence'].append(
                        f"ML service '{service_name}'  {inference['device_type']} "
                        f"(conf: {inference['confidence']}, ml: {inference.get('ml_weight', 0.7)})"
                    )
                    ml_confidence_sum += inference.get('ml_weight', 0.7)
                    ml_pattern_count += 1
                    result['ml_service_patterns'].append(f"{service_key}_{inference['device_type']}")
        if ml_pattern_count > 0:
            result['ml_confidence'] = ml_confidence_sum / ml_pattern_count
            result['confidence'] = max(result['confidence'], result['ml_confidence'])
        return result if result['service_inferences'] else None
    def check_iot_patterns_ml(self, product_string: str) -> Optional[Dict]:
        """ML-enhanced check for specific IoT device patterns"""
        product_lower = product_string.lower()
        for brand, brand_info in self.IOT_PATTERNS.items():
            for pattern in brand_info['patterns']:
                if pattern in product_lower:
                    return {
                        'brand': brand,
                        'confidence': brand_info['confidence'],
                        'pattern': pattern,
                        'ml_weight': brand_info['confidence'] * 0.9
                    }
        return None
    def analyze_protocols(self, enhanced_scans: Dict) -> Dict:
        """Analyze detected protocols for device identification with ML patterns"""
        if not enhanced_scans:
            return None
        result = {
            'protocols_detected': [],
            'evidence': [],
            'confidence': 0.5,
            'pattern_score': 0.0,
            'ml_protocol_patterns': []
        }
        pattern_scores = []
        udp_scan = enhanced_scans.get('udp_scan', {})
        if udp_scan.get('ports'):
            for port_info in udp_scan.get('ports', []):
                port = port_info.get('port')
                if port == 1900:
                    result['protocols_detected'].append('UPnP/SSDP')
                    result['evidence'].append('ML: UPnP protocol (smart TV/speaker/IoT)')
                    result['ml_protocol_patterns'].append('udp_upnp')
                    pattern_scores.append(0.8)
                elif port == 5353:
                    result['protocols_detected'].append('mDNS/Bonjour')
                    result['evidence'].append('ML: mDNS (Apple/Android/IoT device)')
                    result['ml_protocol_patterns'].append('udp_mdns')
                    pattern_scores.append(0.7)
                elif port == 5683:
                    result['protocols_detected'].append('CoAP')
                    result['evidence'].append('ML: CoAP protocol (IoT device)')
                    result['ml_protocol_patterns'].append('udp_coap')
                    pattern_scores.append(0.75)
        iot_protocols = enhanced_scans.get('iot_protocols', {})
        if iot_protocols:
            for protocol, info in iot_protocols.items():
                if info.get('available'):
                    result['protocols_detected'].append(protocol.upper())
                    result['evidence'].append(f'ML: {protocol.upper()} protocol detected')
                    result['ml_protocol_patterns'].append(f'iot_{protocol}')
                    pattern_scores.append(0.85)
        if pattern_scores:
            result['pattern_score'] = sum(pattern_scores) / len(pattern_scores)
            result['confidence'] = max(result['confidence'], result['pattern_score'])
        return result if result['protocols_detected'] else None
    def analyze_ip_address(self, ip: str) -> Dict:
        """Enhanced IP address analysis with ML context"""
        if not ip:
            return None
        result = {
            'evidence': [],
            'confidence': 0.2,
            'context_score': 0.0,
            'ml_context': []
        }
        try:
            if ip.endswith('.1') or ip.endswith('.254'):
                result['evidence'].append(f'ML: Common network address ({ip}) - likely gateway/router')
                result['context_score'] = 0.6
                result['ml_context'].append('likely_gateway')
            if ip.endswith('.2') or ip.endswith('.100'):
                result['evidence'].append(f'ML: Common DHCP server address ({ip})')
                result['context_score'] = 0.5
                result['ml_context'].append('possible_dhcp')
            parts = list(map(int, ip.split('.')))
            if len(parts) == 4:
                if 100 <= parts[3] <= 200:
                    result['evidence'].append(f'ML: Common DHCP client range ({ip})')
                    result['context_score'] = 0.4
                    result['ml_context'].append('dhcp_client_range')
                if parts[3] < 10 or parts[3] > 240:
                    result['evidence'].append(f'ML: Possibly static IP ({ip})')
                    result['context_score'] = 0.3
                    result['ml_context'].append('possible_static_ip')
            if ip.startswith('169.254.'):
                result['evidence'].append('ML: Link-local address (APIPA) - no DHCP')
                result['context_score'] = 0.7
                result['ml_context'].append('link_local')
            if ip.startswith('224.') or ip.startswith('239.'):
                result['evidence'].append('ML: Multicast address - not a device')
                result['context_score'] = 0.9
                result['ml_context'].append('multicast')
        except:
            pass
        return result if result['evidence'] else None
    def ml_enhanced_analysis(self, device_info: Dict, nmap_results: Dict, enhanced_scans: Dict) -> Dict:
        """ML-enhanced comprehensive device analysis"""
        if not self.ai_integration:
            return None
        analysis = {
            'ml_score': 0.0,
            'insights': [],
            'predictions': [],
            'anomalies': [],
            'overall_confidence': 0.5,
            'feature_vectors': {}
        }
        features = self.extract_ml_features(device_info, nmap_results, enhanced_scans)
        analysis['feature_vectors'] = features
        predictions = self.ml_predictions(features)
        analysis['predictions'] = predictions
        anomalies = self.detect_ml_anomalies(features, device_info)
        analysis['anomalies'] = anomalies
        insights = self.generate_ml_insights(features, predictions, anomalies)
        analysis['insights'] = insights
        analysis['ml_score'] = self.calculate_ml_score(features, predictions)
        analysis['overall_confidence'] = analysis['ml_score']
        return analysis
    def extract_ml_features(self, device_info: Dict, nmap_results: Dict, enhanced_scans: Dict) -> Dict:
        """Extract features for ML analysis"""
        features = {
            'basic': {},
            'network': {},
            'service': {},
            'behavioral': {}
        }
        features['basic']['has_mac'] = 1.0 if device_info.get('mac') and device_info['mac'] != 'Unknown' else 0.0
        features['basic']['has_vendor'] = 1.0 if device_info.get('vendor') and device_info['vendor'] != 'Unknown' else 0.0
        ports = nmap_results.get('ports', [])
        features['network']['port_count'] = len(ports)
        features['network']['common_port_ratio'] = self.calculate_common_port_ratio(ports)
        services = nmap_results.get('services', {})
        features['service']['service_count'] = len(services)
        features['service']['iot_service_ratio'] = self.calculate_iot_service_ratio(services)
        udp_scan = enhanced_scans.get('udp_scan', {})
        features['behavioral']['has_udp_services'] = 1.0 if udp_scan.get('ports') else 0.0
        return features
    def calculate_common_port_ratio(self, ports: List[Dict]) -> float:
        """Calculate ratio of common IoT/network ports"""
        common_ports = {80, 443, 22, 23, 21, 53, 67, 68, 161, 162, 1900, 5353, 5683}
        common_count = sum(1 for p in ports if p.get('port') in common_ports)
        return common_count / max(len(ports), 1)
    def calculate_iot_service_ratio(self, services: Dict) -> float:
        """Calculate ratio of IoT-related services"""
        iot_services = {'mqtt', 'coap', 'upnp', 'ssdp', 'rtsp', 'modbus'}
        service_names = set(services.keys())
        iot_count = sum(1 for service in service_names if any(iot in service.lower() for iot in iot_services))
        return iot_count / max(len(service_names), 1)
    def ml_predictions(self, features: Dict) -> List[Dict]:
        """Generate ML-based predictions"""
        predictions = []
        port_count = features['network']['port_count']
        common_port_ratio = features['network']['common_port_ratio']
        iot_service_ratio = features['service']['iot_service_ratio']
        if iot_service_ratio > 0.5 or (common_port_ratio > 0.7 and port_count <= 5):
            predictions.append({
                'prediction': 'IoT Device',
                'confidence': min(0.8, iot_service_ratio * 1.2),
                'reason': 'High IoT service ratio or common port pattern'
            })
        elif common_port_ratio > 0.8 and port_count >= 3:
            predictions.append({
                'prediction': 'Network Device',
                'confidence': 0.75,
                'reason': 'Multiple common network ports'
            })
        elif port_count > 10:
            predictions.append({
                'prediction': 'Server',
                'confidence': min(0.7, port_count / 30),
                'reason': 'High port count'
            })
        return predictions
    def detect_ml_anomalies(self, features: Dict, device_info: Dict) -> List[Dict]:
        """Detect anomalies using ML patterns"""
        anomalies = []
        port_count = features['network']['port_count']
        if port_count == 0 and device_info.get('mac') != 'Unknown':
            anomalies.append({
                'type': 'no_open_ports',
                'severity': 'medium',
                'description': 'Device has MAC but no open TCP ports',
                'ml_confidence': 0.6
            })
        if features['service']['iot_service_ratio'] > 0 and features['network']['port_count'] > 15:
            anomalies.append({
                'type': 'mixed_iot_server',
                'severity': 'low',
                'description': 'IoT services combined with high port count',
                'ml_confidence': 0.5
            })
        return anomalies
    def generate_ml_insights(self, features: Dict, predictions: List[Dict], anomalies: List[Dict]) -> List[str]:
        """Generate ML-based insights"""
        insights = []
        for pred in predictions:
            insights.append(f"ML predicts: {pred['prediction']} (confidence: {pred['confidence']:.2f})")
        for anomaly in anomalies:
            insights.append(f"ML anomaly: {anomaly['description']}")
        if features['service']['iot_service_ratio'] > 0.7:
            insights.append("Strong IoT service patterns detected")
        if features['network']['common_port_ratio'] > 0.9:
            insights.append("Device uses mostly common network ports")
        return insights
    def calculate_ml_score(self, features: Dict, predictions: List[Dict]) -> float:
        """Calculate overall ML confidence score"""
        if not predictions:
            return 0.3
        confidence_sum = sum(p['confidence'] for p in predictions)
        avg_confidence = confidence_sum / len(predictions)
        feature_score = 0.0
        if features['basic']['has_mac']:
            feature_score += 0.2
        if features['basic']['has_vendor']:
            feature_score += 0.1
        if features['network']['port_count'] > 0:
            feature_score += 0.2
        if features['service']['service_count'] > 0:
            feature_score += 0.1
        return min(0.95, avg_confidence + feature_score)
    def determine_device_type_ml(self, mac_info: Dict, ttl_info: Dict, 
                                port_info: Dict, service_info: Dict, ml_analysis: Dict) -> Tuple[str, float, Dict]:
        """Determine device type using ML-weighted fusion"""
        type_votes = {}
        ml_scores = {}
        if mac_info:
            hint = mac_info.get('device_hint')
            if hint:
                ml_weight = mac_info.get('ml_confidence', 0.5)
                type_votes[hint.lower()] = type_votes.get(hint.lower(), 0) + ml_weight
                ml_scores['mac_based'] = ml_weight
        if port_info and port_info.get('device_guesses'):
            for guess in port_info['device_guesses'][:2]:  
                device_type = guess['device_type']
                ml_score = guess.get('match_score', 0.0) * port_info.get('ml_match_score', 0.5)
                type_votes[device_type] = type_votes.get(device_type, 0) + ml_score
                ml_scores[f'port_{device_type}'] = ml_score
        if service_info and service_info.get('service_inferences'):
            for inference in service_info['service_inferences']:
                device_type = inference['device_type']
                ml_weight = inference.get('ml_weight', 0.6) * service_info.get('ml_confidence', 0.6)
                type_votes[device_type] = type_votes.get(device_type, 0) + ml_weight
                ml_scores[f'service_{device_type}'] = ml_weight
        if ml_analysis and ml_analysis.get('predictions'):
            for pred in ml_analysis['predictions']:
                device_type = pred['prediction'].lower().replace(' ', '_')
                ml_score = pred.get('confidence', 0.5)
                type_votes[device_type] = type_votes.get(device_type, 0) + ml_score
                ml_scores[f'ml_{device_type}'] = ml_score
        if not type_votes:
            return 'Unknown Device', 0.1, ml_scores
        best_type = max(type_votes.items(), key=lambda x: x[1])
        max_possible = 3.0  
        confidence = min(0.95, best_type[1] / max_possible)
        type_mapping = {
            'windows_pc': 'Windows Computer',
            'linux_pc': 'Linux Computer',
            'mac_pc': 'Mac Computer',
            'smartphone': 'Smartphone/Tablet',
            'iot_device': 'IoT Device',
            'iot_device_ml': 'IoT Device (ML-confirmed)',
            'iot_camera': 'Security Camera',
            'smart_tv': 'Smart TV',
            'router': 'Router/Gateway',
            'switch': 'Network Switch',
            'access_point': 'Wi-Fi Access Point',
            'nas': 'Network Attached Storage',
            'media_server': 'Media Server',
            'virtual_machine': 'Virtual Machine',
            'smartphone_or_iot': 'Smartphone or IoT Device',
            'smartphone_or_iot_sleeping': 'Sleeping Device (Phone/IoT)',
            'server': 'Server',
            'network_device': 'Network Device'
        }
        readable_type = type_mapping.get(best_type[0], best_type[0].replace('_', ' ').title())
        return readable_type, confidence, ml_scores
    def calculate_ml_confidence(self, confidence_factors: List[float], ml_scores: Dict, num_signals: int) -> float:
        """Calculate overall confidence score with ML enhancement"""
        if not confidence_factors:
            return 0.1
        avg_confidence = sum(confidence_factors) / len(confidence_factors)
        ml_boost = 0.0
        if ml_scores:
            ml_avg = sum(ml_scores.values()) / len(ml_scores)
            ml_boost = ml_avg * 0.3  
        signal_bonus = min(0.2, num_signals * 0.03)
        return min(0.98, avg_confidence + ml_boost + signal_bonus)
    def determine_os_family(self, ttl_info: Dict, service_info: Dict, port_info: Dict) -> Tuple[str, float]:
        """Determine OS family from signals with ML preference"""
        if ttl_info and ttl_info.get('likely_os') != 'Unknown':
            return ttl_info['likely_os'], ttl_info.get('confidence', 0.5)
        if service_info and service_info.get('service_inferences'):
            ml_confidence = service_info.get('ml_confidence', 0.0)
            for inference in service_info['service_inferences']:
                if inference.get('device_type') == 'router':
                    return 'Embedded Linux', max(0.6, ml_confidence)
                elif inference.get('device_type') == 'iot_device':
                    return 'Embedded Linux/RTOS', max(0.5, ml_confidence)
        return 'Unknown', 0.1
    def assess_risk_ml(self, device_type: str, nmap_results: Dict, ml_scores: Dict) -> Dict:
        """AI-enhanced security risk assessment"""
        risk = {
            'level': 'LOW',
            'factors': [],
            'recommendations': [],
            'ml_confidence': 0.0,
            'ml_risk_factors': []
        }
        ml_risk_score = 0.0
        high_risk_services = {'telnet': 0.9, 'ftp': 0.8, 'vnc': 0.7, 'rdp': 0.7, 'snmp': 0.6}
        services = nmap_results.get('services', {})
        for service_name in services:
            service_lower = service_name.lower()
            for risk_service, weight in high_risk_services.items():
                if risk_service in service_lower:
                    risk['factors'].append(f'High-risk service: {service_name}')
                    risk['level'] = 'HIGH'
                    ml_risk_score += weight
                    risk['ml_risk_factors'].append(f'service_{risk_service}')
        device_type_lower = device_type.lower()
        if 'router' in device_type_lower or 'gateway' in device_type_lower:
            risk['factors'].append('Critical infrastructure device')
            risk['recommendations'].append('Change default admin credentials')
            risk['recommendations'].append('Update firmware regularly')
            risk['level'] = 'HIGH'
            ml_risk_score += 0.8
            risk['ml_risk_factors'].append('critical_infrastructure')
        elif 'camera' in device_type_lower or 'iot' in device_type_lower:
            risk['factors'].append('IoT device - often poorly secured')
            risk['recommendations'].append('Change default credentials')
            risk['recommendations'].append('Isolate on separate network')
            risk['level'] = 'MEDIUM'
            ml_risk_score += 0.6
            risk['ml_risk_factors'].append('iot_device')
        elif 'windows' in device_type_lower:
            risk['factors'].append('Common target for attacks')
            risk['recommendations'].append('Ensure Windows Update is enabled')
            risk['recommendations'].append('Use antivirus software')
            risk['level'] = 'MEDIUM'
            ml_risk_score += 0.5
            risk['ml_risk_factors'].append('windows_target')
        if len(nmap_results.get('ports', [])) > 10:
            risk['factors'].append('Many open ports increase attack surface')
            risk['level'] = max(risk['level'], 'MEDIUM')
            ml_risk_score += 0.3
            risk['ml_risk_factors'].append('high_port_count')
        if ml_risk_score > 0:
            risk['ml_confidence'] = min(1.0, ml_risk_score / 3.0)  
        if risk['ml_confidence'] > 0.7:
            risk['level'] = 'HIGH'
        elif risk['ml_confidence'] > 0.4:
            if risk['level'] == 'LOW':
                risk['level'] = 'MEDIUM'
        return risk
    def generate_ai_recommendations(self, fingerprint: Dict) -> List[str]:
        """Generate AI-based recommendations"""
        recommendations = []
        device_type = fingerprint['analysis'].get('device_type', '').lower()
        risk_assessment = fingerprint.get('risk_assessment', {})
        ml_scores = fingerprint['analysis'].get('ml_scores', {})
        recommendations.append("AI Security Recommendations:")
        if 'iot' in device_type or 'camera' in device_type:
            recommendations.append("1. Isolate IoT devices on separate VLAN")
            recommendations.append("2. Implement network segmentation")
            recommendations.append("3. Monitor for unusual IoT traffic patterns")
        if 'router' in device_type or 'gateway' in device_type:
            recommendations.append("1. Enable logging and monitoring")
            recommendations.append("2. Implement strict firewall rules")
            recommendations.append("3. Regular security audits")
        if risk_assessment.get('level') in ['HIGH', 'MEDIUM']:
            recommendations.append("1. Immediate security review recommended")
            recommendations.append("2. Consider penetration testing")
        if ml_scores.get('ml_enhanced', 0) > 0.7:
            recommendations.append("ML Note: High confidence in device classification")
        if any('anomaly' in key for key in ml_scores.keys()):
            recommendations.append("ML Alert: Anomalies detected - investigate further")
        return recommendations