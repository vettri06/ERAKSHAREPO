"""
AI-Based Anomaly Detection Module
Optimized for IoT-23 labeled conn.log files on Windows
"""
import json
import logging
import numpy as np
import pickle
import pandas as pd
import os
import glob
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import PureWindowsPath
from collections import defaultdict, Counter
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler
import warnings
warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)
class AnomalyDetector:
    """Anomaly detection for IoT devices using IoT-23 labeled logs"""
    def __init__(self, model_path=None, history_file="anomaly_history.json"):
        if model_path is None:
            self.model_path = os.path.join(os.path.dirname(__file__), "models", "anomaly_detector.pkl")
        else:
            self.model_path = model_path
        self.history_file = history_file
        self.model = None
        self.scaler = RobustScaler()
        self.device_history = self.load_history()
        self.anomaly_threshold = 0.7
        self.EXPECTED_FEATURES = 25  
        self.MALWARE_INDICATORS = {
            'ports': [23, 2323, 5555, 6667, 7547, 8080, 8443, 37215, 52869],
            'services': ['telnet', 'ssh', 'ftp', 'irc', 'unknown'],
            'malware_families': ['Mirai', 'Torii', 'Okiru', 'Linux/Hajime', 'Gafgyt'],
            'patterns': ['PartOfAHorizontalPortScan', 'DDoS', 'C&C', 'Attack']
        }
        self.load_or_train_model()
    def convert_windows_path(self, path: str) -> str:
        """Convert Windows path to proper format"""
        return str(PureWindowsPath(path))
    def load_history(self) -> Dict:
        """Load device history from file"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading history: {e}")
        return {}
    def save_history(self):
        """Save device history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(self.device_history, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving history: {e}")
    def parse_iot23_conn_log(self, file_path: str) -> pd.DataFrame:
        """Parse IoT-23 conn.log.labeled file"""
        file_path = self.convert_windows_path(file_path)
        if not os.path.exists(file_path):
            logger.error(f"File does not exist: {file_path}")
            return pd.DataFrame()
        logger.info(f"Parsing conn.log: {file_path}")
        try:
            data_lines = []
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if not line.startswith('#'):
                        data_lines.append(line.strip())
            if not data_lines:
                logger.warning(f"No data lines in {file_path}")
                return pd.DataFrame()
            records = []
            for i, line in enumerate(data_lines[:50000]):
                try:
                    parts = line.split('\t')
                    if len(parts) < 10:
                        continue
                    record = {
                        'ts': float(parts[0]) if parts[0] != '-' else 0.0,
                        'id.orig_h': parts[2] if len(parts) > 2 else '',
                        'id.orig_p': int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0,
                        'id.resp_h': parts[4] if len(parts) > 4 else '',
                        'id.resp_p': int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0,
                        'proto': parts[6] if len(parts) > 6 else '',
                        'service': parts[7] if len(parts) > 7 else '',
                        'duration': float(parts[8]) if len(parts) > 8 and parts[8] != '-' else 0.0,
                        'orig_bytes': int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
                        'resp_bytes': int(parts[10]) if len(parts) > 10 and parts[10].isdigit() else 0,
                        'conn_state': parts[11] if len(parts) > 11 else '',
                        'orig_pkts': int(parts[16]) if len(parts) > 16 and parts[16].isdigit() else 0,
                        'resp_pkts': int(parts[18]) if len(parts) > 18 and parts[18].isdigit() else 0,
                    }
                    if len(parts) > 21:
                        record['label'] = parts[21]
                    elif len(parts) > 20:
                        record['label'] = parts[20]
                    records.append(record)
                except Exception as e:
                    if i < 10:
                        logger.debug(f"Error parsing line {i}: {e}")
                    continue
            if not records:
                logger.warning(f"No valid records from {file_path}")
                return pd.DataFrame()
            df = pd.DataFrame(records)
            df['timestamp'] = pd.to_datetime(df['ts'], unit='s')
            if 'label' in df.columns:
                df['is_malicious'] = df['label'].apply(
                    lambda x: 1 if isinstance(x, str) and any(
                        keyword in x for keyword in ['Malicious', 'PartOfAHorizontalPortScan', 
                                                     'Attack', 'DDoS', 'C&C']
                    ) else 0
                )
            logger.info(f"Parsed {len(df)} connections from {file_path}")
            return df
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return pd.DataFrame()
    def extract_anomaly_features(self, df: pd.DataFrame, device_ip: str = None) -> np.ndarray:
        """Extract anomaly detection features from connection data - FIXED to 20 features"""
        if df.empty:
            return np.zeros(self.EXPECTED_FEATURES)
        features = []
        if device_ip:
            device_data = df[
                (df['id.orig_h'] == device_ip) | 
                (df['id.resp_h'] == device_ip)
            ]
        else:
            device_data = df
        if device_data.empty:
            return np.zeros(self.EXPECTED_FEATURES)
        try:
            total_connections = len(device_data)
            features.append(np.log1p(total_connections))
            total_bytes = device_data['orig_bytes'].sum() + device_data['resp_bytes'].sum()
            features.append(np.log1p(total_bytes + 1))
            total_packets = device_data['orig_pkts'].sum() + device_data['resp_pkts'].sum()
            features.append(np.log1p(total_packets + 1))
            avg_duration = device_data['duration'].mean()
            features.append(np.log1p(avg_duration + 1e-6))
            unique_ports = device_data['id.resp_p'].nunique()
            features.append(float(unique_ports))
            if total_connections > 0:
                port_scan_ratio = unique_ports / total_connections
                features.append(port_scan_ratio)
            else:
                features.append(0.0)
            proto_counts = device_data['proto'].value_counts()
            for proto in ['tcp', 'udp', 'icmp']:
                count = proto_counts.get(proto, 0)
                features.append(float(count / max(total_connections, 1)))
            suspicious_states = ['REJ', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'S0']
            suspicious_count = device_data['conn_state'].isin(suspicious_states).sum()
            features.append(float(suspicious_count / max(total_connections, 1)))
            suspicious_services = ['telnet', 'ssh', 'ftp', 'irc', '']
            service_counts = device_data['service'].str.lower().value_counts()
            suspicious_service_count = 0
            for service in suspicious_services:
                suspicious_service_count += service_counts.get(service, 0)
            features.append(float(suspicious_service_count / max(total_connections, 1)))
            orig_bytes_total = device_data['orig_bytes'].sum()
            resp_bytes_total = device_data['resp_bytes'].sum()
            if resp_bytes_total > 0:
                byte_asymmetry = orig_bytes_total / resp_bytes_total
                features.append(np.log1p(byte_asymmetry + 1))
            else:
                features.append(0.0)
            orig_pkts_total = device_data['orig_pkts'].sum()
            resp_pkts_total = device_data['resp_pkts'].sum()
            if resp_pkts_total > 0:
                packet_asymmetry = orig_pkts_total / resp_pkts_total
                features.append(np.log1p(packet_asymmetry + 1))
            else:
                features.append(0.0)
            unique_destinations = device_data['id.resp_h'].nunique()
            features.append(float(unique_destinations))
            if 'is_malicious' in device_data.columns:
                malware_count = device_data['is_malicious'].sum()
                features.append(float(malware_count / max(total_connections, 1)))
            else:
                features.append(0.0)
            malware_port_count = device_data['id.resp_p'].isin(self.MALWARE_INDICATORS['ports']).sum()
            features.append(float(malware_port_count / max(total_connections, 1)))
            avg_packet_size = total_bytes / max(total_packets, 1)
            features.append(np.log1p(avg_packet_size + 1))
            if len(device_data) > 1:
                timestamps = pd.to_datetime(device_data['ts'], unit='s')
                time_range = (timestamps.max() - timestamps.min()).total_seconds()
                if time_range > 0:
                    connection_rate = total_connections / time_range
                    features.append(np.log1p(connection_rate + 1))
                else:
                    features.append(0.0)
            else:
                features.append(0.0)
        except Exception as e:
            logger.error(f"Error extracting anomaly features: {e}")
            return np.zeros(self.EXPECTED_FEATURES)
        if len(features) < self.EXPECTED_FEATURES:
            features.extend([0.0] * (self.EXPECTED_FEATURES - len(features)))
        elif len(features) > self.EXPECTED_FEATURES:
            features = features[:self.EXPECTED_FEATURES]
        return np.array(features).reshape(1, -1)
    def train_from_json(self, json_file: str, save_model: bool = True):
        """Train anomaly detector from synthetic JSON data"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            logger.info(f"Loading synthetic anomaly dataset from: {json_file}")
            
            all_features = []
            
            for item in data:
                # Map JSON to input format
                device_info = {
                    'vendor': item.get('vendor', ''),
                    'ttl': item.get('ttl', 64),
                    'response_time': item.get('response_time', 0),
                    'server_header': item.get('server_header', ''),
                    'ports': item.get('ports', []),
                    'services': item.get('services', []),
                    'mac': '',
                    'device_type': item.get('device_type', 'Unknown')
                }
                
                nmap_results = {
                    'ports': [{'port': p} for p in item.get('ports', [])],
                    'services': {s: {} for s in item.get('services', [])}
                }
                
                features = self.extract_basic_anomaly_features('0.0.0.0', device_info, nmap_results)
                all_features.append(features.flatten())
                
            X = np.array(all_features)
            logger.info(f"Training Anomaly Detector with {X.shape[0]} samples (shape: {X.shape})")
            
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            self.model = IsolationForest(
                n_estimators=200,
                contamination=0.1, # Expecting ~10% anomalies
                random_state=42,
                bootstrap=True,
                n_jobs=-1
            )
            
            logger.info("Training Isolation Forest (Boosted)...")
            self.model.fit(X_scaled)
            
            predictions = self.model.predict(X_scaled)
            anomaly_count = sum(predictions == -1)
            logger.info(f"Detected {anomaly_count} anomalies ({anomaly_count/len(X)*100:.1f}%) in training set")
            
            if save_model:
                self.save_model()
                
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly detector from JSON: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False

    def train_from_iot23_directory(self, dataset_dir: str, save_model: bool = True):
        """Train anomaly detector from IoT-23 dataset directory AND synthetic data"""
        dataset_dir = self.convert_windows_path(dataset_dir)
        if not os.path.exists(dataset_dir):
            logger.error(f"Dataset directory does not exist: {dataset_dir}")
            return
        
        logger.info(f"Training anomaly detector from IoT-23 directory: {dataset_dir}")
        
        # 1. Load and Aggregate IoT-23 Data
        patterns = [
            os.path.join(dataset_dir, "**", "bro", "conn.log.labeled"),
            os.path.join(dataset_dir, "**", "conn.log.labeled"),
            os.path.join(dataset_dir, "**", "*.log")
        ]
        conn_files = []
        for pattern in patterns:
            files = glob.glob(pattern, recursive=True)
            conn_files.extend(files)
            if files:
                break
        
        conn_files = list(set(conn_files))
        logger.info(f"Found {len(conn_files)} log files")
        
        all_features = []
        device_aggregation = {}
        
        for i, conn_file in enumerate(conn_files):
            logger.info(f"[{i+1}/{len(conn_files)}] Processing: {os.path.basename(conn_file)}")
            try:
                df = self.parse_iot23_conn_log(conn_file)
                if df.empty: continue
                
                if len(df) > 50000:
                    df = df.sample(n=50000, random_state=42)
                
                for _, row in df.iterrows():
                    # Similar aggregation logic as Classifier
                    src_ip = row.get('id.orig_h')
                    dst_ip = row.get('id.resp_h')
                    dst_port = row.get('id.resp_p')
                    service = row.get('service')
                    label = row.get('label', '')
                    
                    # Determine device type from label
                    d_type = 'Unknown'
                    if 'Benign' in label: d_type = 'Benign'
                    elif label: d_type = 'Malicious'
                    
                    if src_ip not in device_aggregation:
                        device_aggregation[src_ip] = {'ports': set(), 'services': set(), 'type': d_type}
                    
                    if dst_ip not in device_aggregation:
                        device_aggregation[dst_ip] = {'ports': set(), 'services': set(), 'type': d_type}
                        
                    if dst_port:
                        try: device_aggregation[dst_ip]['ports'].add(int(dst_port))
                        except: pass
                        
                    if service and service != '-':
                        device_aggregation[dst_ip]['services'].add(service)
                        
            except Exception as e:
                logger.error(f"Error processing {conn_file}: {e}")
                continue
                
        # Convert aggregated IoT-23 data to features
        logger.info(f"Aggregated {len(device_aggregation)} IPs from IoT-23")
        for ip, data in device_aggregation.items():
            if not data['ports'] and not data['services']: continue
            
            device_info = {
                'vendor': '',
                'ttl': 64,
                'response_time': 0,
                'server_header': '',
                'ports': list(data['ports']),
                'services': list(data['services']),
                'device_type': data['type']
            }
            nmap_results = {
                'ports': [{'port': p} for p in data['ports']],
                'services': {s: {} for s in data['services']}
            }
            
            features = self.extract_basic_anomaly_features(ip, device_info, nmap_results)
            all_features.append(features.flatten())
            
        # 2. Load Synthetic Data
        synthetic_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "synthetic_iot_data.json")
        if os.path.exists(synthetic_file):
            logger.info(f"Merging with synthetic data from {synthetic_file}")
            try:
                with open(synthetic_file, 'r') as f:
                    syn_data = json.load(f)
                
                for item in syn_data:
                    device_info = {
                        'vendor': item.get('vendor', ''),
                        'ttl': item.get('ttl', 64),
                        'response_time': item.get('response_time', 0),
                        'server_header': item.get('server_header', ''),
                        'ports': item.get('ports', []),
                        'services': item.get('services', []),
                        'device_type': item.get('device_type', 'Unknown')
                    }
                    nmap_results = {
                        'ports': [{'port': p} for p in item.get('ports', [])],
                        'services': {s: {} for s in item.get('services', [])}
                    }
                    features = self.extract_basic_anomaly_features('0.0.0.0', device_info, nmap_results)
                    all_features.append(features.flatten())
            except Exception as e:
                logger.error(f"Error loading synthetic data: {e}")

        if not all_features:
            logger.error("No features extracted from dataset")
            return

        X = np.array(all_features)
        logger.info(f"Training Anomaly Detector with {X.shape[0]} samples (shape: {X.shape})")
        
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.1,  
            random_state=42,
            bootstrap=True,
            n_jobs=-1
        )
        
        logger.info("Training Isolation Forest (Combined)...")
        self.model.fit(X_scaled)
        
        predictions = self.model.predict(X_scaled)
        anomaly_count = sum(predictions == -1)
        logger.info(f"Detected {anomaly_count} anomalies ({anomaly_count/len(X)*100:.1f}%) in training set")
        
        if save_model:
            self.save_model()
    def detect_anomalies(self, ip: str, device_info: Dict, nmap_results: Dict, 
                        traffic_data: List[Dict] = None) -> Dict:
        """Detect anomalies for a device"""
        try:
            scan_data = {
                'ports': nmap_results.get('ports', []),
                'services': nmap_results.get('services', {}),
                'device_type': device_info.get('device_type', 'Unknown')
            }
            self.update_device_history(ip, scan_data)
            features = self.extract_basic_anomaly_features(ip, device_info, nmap_results)
            if self.model is None:
                logger.warning("Anomaly detection model not available, using rule-based")
                return self.rule_based_anomaly_detection(ip, device_info, nmap_results)
            if features.shape[1] != self.EXPECTED_FEATURES:
                logger.warning(f"Feature shape mismatch: got {features.shape[1]}, expected {self.EXPECTED_FEATURES}")
                return self.rule_based_anomaly_detection(ip, device_info, nmap_results)
            features_scaled = self.scaler.transform(features)
            anomaly_score = self.model.decision_function(features_scaled)[0]
            normalized_score = 1.0 / (1.0 + np.exp(-anomaly_score))
            reasons = self.get_anomaly_reasons(features.flatten())
            result = {
                'ip': ip,
                'anomaly_score': float(normalized_score),
                'is_anomalous': normalized_score > self.anomaly_threshold,
                'reasons': reasons,
                'ml_model': 'IsolationForest',
                'threshold': self.anomaly_threshold,
                'features_used': features.shape[1]
            }
            if result['is_anomalous']:
                logger.warning(f"Anomaly detected for {ip}: score={normalized_score:.3f}")
            return result
        except Exception as e:
            logger.error(f"Anomaly detection failed for {ip}: {e}")
            return self.rule_based_anomaly_detection(ip, device_info, nmap_results)
    def extract_basic_anomaly_features(self, ip: str, device_info: Dict, 
                                      nmap_results: Dict) -> np.ndarray:
        """Extract basic anomaly features from scan data - FIXED to 25 features"""
        features = []
        try:
            # 1. Port Count
            ports = [p.get('port', 0) for p in nmap_results.get('ports', [])]
            # Handle JSON direct input
            if not ports and 'ports' in device_info:
                ports = device_info['ports']
                
            features.append(float(len(ports)))

            # 2. High Risk Ports
            high_risk_ports = {23, 2323, 5555, 6667, 7547, 8080, 8443, 22, 21, 3389}
            high_risk_count = len(set(ports).intersection(high_risk_ports))
            features.append(float(high_risk_count))

            # 3-6. Suspicious Services
            services = nmap_results.get('services', {})
            # Handle JSON direct input
            if not services and 'services' in device_info:
                services = {s: {} for s in device_info['services']}

            suspicious_services = ['telnet', 'ftp', 'vnc', 'snmp']
            for svc in suspicious_services:
                has_service = any(svc in name.lower() for name in services.keys())
                features.append(float(has_service))

            # 7. IoT Device Type
            device_type = device_info.get('device_type', '').lower()
            is_iot = any(keyword in device_type for keyword in ['iot', 'camera', 'smart', 'bot'])
            features.append(float(is_iot))

            # 8. Unknown Vendor
            vendor = device_info.get('vendor', '').lower()
            unknown_vendor = vendor == 'unknown' or not vendor
            features.append(float(unknown_vendor))

            # 9. Unknown MAC
            mac = device_info.get('mac', '').lower()
            unknown_mac = 'unknown' in mac or not mac
            features.append(float(unknown_mac))

            # 10-12. Port Categories
            well_known = len([p for p in ports if 0 < p < 1024])
            registered = len([p for p in ports if 1024 <= p < 49151])
            dynamic = len([p for p in ports if p >= 49151])
            features.extend([
                float(well_known),
                float(registered),
                float(dynamic)
            ])

            # 13-14. HTTP/HTTPS
            has_http = any('http' in s.lower() for s in services.keys())
            has_https = any('https' in s.lower() for s in services.keys())
            features.extend([
                float(has_http),
                float(has_https)
            ])

            # 15-17. IoT Protocols
            iot_protocols = ['mqtt', 'coap', 'upnp']
            for proto in iot_protocols:
                has_proto = any(proto in s.lower() for s in services.keys())
                features.append(float(has_proto))

            # 18. Service Count Log
            service_count = len(services)
            features.append(np.log1p(service_count + 1))
            
            # 19. Placeholder (was 0.0) -> Reused for TTL
            ttl = float(device_info.get('ttl', 64))
            features.append(np.log1p(ttl)) # Log normalized TTL

            # 20. Placeholder -> Reused for Response Time
            resp_time = float(device_info.get('response_time', 0.0))
            features.append(resp_time)

            # --- NEW FEATURES (5) ---
            
            # 21. Server Header Length
            server_header = device_info.get('server_header', '')
            features.append(float(len(server_header)))

            # 22. Known Web Server
            web_servers = ['apache', 'nginx', 'jetty', 'iis', 'lighttpd']
            is_known_server = any(ws in server_header.lower() for ws in web_servers)
            features.append(float(is_known_server))
            
            # 23. Empty Server Header (Suspicious if HTTP is present)
            empty_header = len(server_header) == 0 and (has_http or has_https)
            features.append(float(empty_header))

            # 24. High Port Usage Ratio
            if len(ports) > 0:
                features.append(float(dynamic / len(ports)))
            else:
                features.append(0.0)
                
            # 25. Reserved
            features.append(0.0)

        except Exception as e:
            logger.error(f"Error extracting basic anomaly features: {e}")
            return np.zeros(self.EXPECTED_FEATURES)

        if len(features) < self.EXPECTED_FEATURES:
            features.extend([0.0] * (self.EXPECTED_FEATURES - len(features)))
        elif len(features) > self.EXPECTED_FEATURES:
            features = features[:self.EXPECTED_FEATURES]

        return np.array(features).reshape(1, -1)
    def get_anomaly_reasons(self, feature_vector: np.ndarray) -> List[str]:
        """Get human-readable reasons for anomaly"""
        reasons = []
        reason_mapping = [
            (0, "Many open ports"),
            (1, "High-risk IoT ports detected"),
            (2, "Telnet service active"),
            (3, "FTP service active"),
            (4, "VNC service active"),
            (5, "SNMP service active"),
            (6, "IoT device type detected"),
            (7, "Unknown vendor"),
            (8, "Unknown MAC address"),
            (9, "Many well-known ports"),
            (10, "Many registered ports"),
            (11, "Many dynamic ports"),
            (12, "HTTP service detected"),
            (13, "HTTPS service detected"),
            (14, "MQTT protocol detected"),
            (15, "CoAP protocol detected"),
            (16, "UPnP protocol detected"),
            (17, "Many services running"),
            (18, "Large response sizes")
        ]
        for i, (feature_idx, reason) in enumerate(reason_mapping):
            if i < len(feature_vector) and feature_vector[i] > 0.5:
                reasons.append(f"{reason} (score: {feature_vector[i]:.2f})")
        if not reasons:
            reasons = ["No specific anomaly indicators detected"]
        return reasons[:3]
    def update_device_history(self, ip: str, scan_data: Dict):
        """Update history for a device"""
        if ip not in self.device_history:
            self.device_history[ip] = {
                'first_seen': datetime.now().isoformat(),
                'scans': []
            }
        current_scan = {
            'timestamp': datetime.now().isoformat(),
            'open_ports': [p.get('port') for p in scan_data.get('ports', [])],
            'services': list(scan_data.get('services', {}).keys()),
            'device_type': scan_data.get('device_type', 'Unknown')
        }
        self.device_history[ip]['scans'].append(current_scan)
        if len(self.device_history[ip]['scans']) > 50:
            self.device_history[ip]['scans'] = self.device_history[ip]['scans'][-50:]
        self.save_history()
    def rule_based_anomaly_detection(self, ip: str, device_info: Dict, 
                                    nmap_results: Dict) -> Dict:
        """Fallback to rule-based anomaly detection"""
        reasons = []
        anomaly_score = 0.0
        ports = [p.get('port', 0) for p in nmap_results.get('ports', [])]
        mirai_ports = {23, 2323, 5555, 6667}
        mirai_count = len(set(ports).intersection(mirai_ports))
        if mirai_count > 0:
            reasons.append(f"Mirai malware indicators: {mirai_count} suspicious ports")
            anomaly_score += 0.4
        services = nmap_results.get('services', {})
        if any('telnet' in name.lower() for name in services.keys()):
            reasons.append("Telnet service (common in IoT botnets)")
            anomaly_score += 0.5
        if len(ports) > 10:
            reasons.append(f"Many open ports ({len(ports)})")
            anomaly_score += 0.3
        device_type = device_info.get('device_type', 'Unknown')
        if device_type == 'Unknown':
            reasons.append("Unknown device type")
            anomaly_score += 0.2
        anomaly_score = min(1.0, anomaly_score)
        return {
            'ip': ip,
            'anomaly_score': float(anomaly_score),
            'is_anomalous': anomaly_score > self.anomaly_threshold,
            'reasons': reasons,
            'ml_model': 'rule_based',
            'threshold': self.anomaly_threshold
        }
    def load_or_train_model(self):
        """Load existing model or initialize new one"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    saved_data = pickle.load(f)
                    self.model = saved_data['model']
                    self.scaler = saved_data['scaler']
                    logger.info(f" Loaded anomaly detection model from {self.model_path}")
                    if hasattr(self.model, 'n_estimators'):
                        logger.info(f"  Model type: {self.model.__class__.__name__}")
                        logger.info(f"  Estimators: {self.model.n_estimators}")
                        logger.info(f"  Contamination: {self.model.contamination}")
                    if 'expected_features' in saved_data:
                        self.EXPECTED_FEATURES = saved_data['expected_features']
                    logger.info(f"  Expected features: {self.EXPECTED_FEATURES}")
            else:
                logger.warning(f"  Model file not found: {self.model_path}")
                self.model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
                logger.info("Initialized new anomaly detection model")
        except Exception as e:
            logger.error(f" Error loading anomaly model: {e}")
            self.model = None
    def save_model(self):
        """Save the trained model"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            saved_data = {
                'model': self.model,
                'scaler': self.scaler,
                'timestamp': datetime.now().isoformat(),
                'expected_features': self.EXPECTED_FEATURES
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(saved_data, f)
            logger.info(f"Anomaly model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
