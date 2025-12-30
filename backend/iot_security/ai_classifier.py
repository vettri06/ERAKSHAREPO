"""
AI-Based Device Classification Module
Optimized for IoT-23 labeled conn.log files on Windows
"""
import json
import logging
import numpy as np
import pickle
import pandas as pd
import os
import glob
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from pathlib import PureWindowsPath
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import warnings
warnings.filterwarnings('ignore')
logger = logging.getLogger(__name__)
class AIDeviceClassifier:
    """Machine Learning model for device classification using IoT-23 labeled logs"""
    def __init__(self, model_path=None):
        if model_path is None:
            self.model_path = os.path.join(os.path.dirname(__file__), "models", "device_classifier.pkl")
        else:
            self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.EXPECTED_FEATURES = 30  
        self.CONN_LOG_COLUMNS = [
            'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 
            'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
            'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
            'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
            'tunnel_parents', 'label', 'detailed-label'
        ]
        self.IOT_DEVICE_TYPES = {
            'Benign': 'Benign_Device',
            'Malicious': 'Malicious_Device',
            'PartOfAHorizontalPortScan': 'Scanner',
            'C&C': 'C&C_Server',
            'DDoS': 'DDoS_Attacker',
            'Okiru': 'Mirai_Bot',
            'Torii': 'Torii_Bot',
            'Mirai': 'Mirai_Bot',
            'Android': 'Android_Device',
            'Linux': 'Linux_Device',
            'Windows': 'Windows_Device',
            'Attack': 'Attacker',
            'Botnet': 'Botnet_Node',
            'CoinMiner': 'CoinMiner',
            'Generic': 'Generic_Device'
        }
        self.load_or_train_model()
    def convert_windows_path(self, path: str) -> str:
        """Convert Windows path to proper format"""
        return str(PureWindowsPath(path))
    def parse_conn_log_labeled(self, file_path: str) -> pd.DataFrame:
        """Parse IoT-23 labeled conn.log file"""
        file_path = self.convert_windows_path(file_path)
        if not os.path.exists(file_path):
            logger.error(f"File does not exist: {file_path}")
            return pd.DataFrame()
        logger.info(f"Parsing conn.log.labeled: {file_path}")
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
                logger.warning(f"No valid records parsed from {file_path}")
                return pd.DataFrame()
            df = pd.DataFrame(records)
            if 'label' in df.columns:
                df['device_type'] = df['label'].apply(self.map_label_to_device_type)
            logger.info(f"Parsed {len(df)} records from {file_path}")
            return df
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return pd.DataFrame()
    def map_label_to_device_type(self, label: str) -> str:
        """Map IoT-23 label to device type"""
        if pd.isna(label) or not isinstance(label, str):
            return 'Unknown'
        label_str = label.strip()
        for key, device_type in self.IOT_DEVICE_TYPES.items():
            if key in label_str:
                return device_type
        label_lower = label_str.lower()
        if 'mirai' in label_lower:
            return 'Mirai_Bot'
        elif 'torii' in label_lower:
            return 'Torii_Bot'
        elif 'ddos' in label_lower:
            return 'DDoS_Attacker'
        elif 'scan' in label_lower:
            return 'Scanner'
        elif 'benign' in label_lower:
            return 'Benign_Device'
        elif 'attack' in label_lower:
            return 'Attacker'
        elif 'botnet' in label_lower:
            return 'Botnet_Node'
        return 'Generic_Device'
    def extract_features_from_conn(self, conn_row: pd.Series) -> np.ndarray:
        """Extract ML features from a connection row - FIXED to 25 features"""
        features = []
        try:
            duration = float(conn_row.get('duration', 0))
            features.append(np.log1p(duration + 1e-6))  
            orig_bytes = float(conn_row.get('orig_bytes', 0))
            resp_bytes = float(conn_row.get('resp_bytes', 0))
            total_bytes = orig_bytes + resp_bytes
            features.extend([
                np.log1p(orig_bytes + 1),
                np.log1p(resp_bytes + 1),
                np.log1p(total_bytes + 1)
            ])
            if resp_bytes > 0:
                bytes_ratio = orig_bytes / resp_bytes
                features.append(np.log1p(bytes_ratio + 1))
            else:
                features.append(0.0)
            orig_pkts = float(conn_row.get('orig_pkts', 0))
            resp_pkts = float(conn_row.get('resp_pkts', 0))
            total_pkts = orig_pkts + resp_pkts
            features.extend([
                np.log1p(orig_pkts + 1),
                np.log1p(resp_pkts + 1),
                np.log1p(total_pkts + 1)
            ])
            if resp_pkts > 0:
                pkts_ratio = orig_pkts / resp_pkts
                features.append(np.log1p(pkts_ratio + 1))
            else:
                features.append(0.0)
            orig_port = int(conn_row.get('id.orig_p', 0))
            resp_port = int(conn_row.get('id.resp_p', 0))
            iot_ports = {1883, 8883, 5683, 1900, 5353, 7547, 5555, 6667}
            features.extend([
                float(orig_port in iot_ports),
                float(resp_port in iot_ports),
                float(orig_port < 1024),  
                float(resp_port < 1024),
                float(orig_port > 49151),  
                float(resp_port > 49151)
            ])
            protocol = str(conn_row.get('proto', '')).lower()
            features.extend([
                float(protocol == 'tcp'),
                float(protocol == 'udp'),
                float(protocol == 'icmp')
            ])
            service = str(conn_row.get('service', '')).lower()
            features.extend([
                float('http' in service),
                float('dns' in service),
                float('ssh' in service),
                float('telnet' in service),
                float('ftp' in service)
            ])
            state = str(conn_row.get('conn_state', '')).upper()
            suspicious_states = ['REJ', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'S0']
            features.append(float(state in suspicious_states))
            if duration > 0:
                features.extend([
                    total_bytes / duration,
                    total_pkts / duration
                ])
            else:
                features.extend([0.0, 0.0])
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return np.zeros(self.EXPECTED_FEATURES)
        if len(features) < self.EXPECTED_FEATURES:
            features.extend([0.0] * (self.EXPECTED_FEATURES - len(features)))
        elif len(features) > self.EXPECTED_FEATURES:
            features = features[:self.EXPECTED_FEATURES]
        return np.array(features)
    def train_from_json(self, json_file: str, save_model: bool = True, 
                       test_size: float = 0.2) -> float:
        """Train model from synthetic JSON data"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            logger.info(f"Loading synthetic dataset from: {json_file}")
            
            X = []
            y = []
            
            for item in data:
                # Map JSON fields to extract_features_from_scans input format
                device_info = {
                    'vendor': item.get('vendor', ''),
                    'ttl': item.get('ttl', 64),
                    'response_time': item.get('response_time', 0),
                    'server_header': item.get('server_header', ''),
                    'ports': item.get('ports', []),
                    'services': item.get('services', []),
                    'mac': '' # Synthetic data might not have MAC, or we can mock it
                }
                
                # Mock Nmap results as we passed ports/services in device_info
                nmap_results = {
                    'ports': [{'port': p} for p in item.get('ports', [])],
                    'services': {s: {} for s in item.get('services', [])}
                }
                
                enhanced_scans = {} # Can be populated if needed
                
                features = self.extract_features_from_scans(device_info, nmap_results, enhanced_scans)
                label = item.get('device_type', 'Unknown')
                
                X.append(features)
                y.append(label)
                
            X = np.array(X)
            y = np.array(y)
            
            logger.info(f"Training with {len(X)} samples, {len(np.unique(y))} classes")
            
            # Encode labels
            self.label_encoder.fit(y)
            y_encoded = self.label_encoder.transform(y)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
            )
            
            # Scale features
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Initialize model (Gradient Boosting)
            self.model = GradientBoostingClassifier(
                n_estimators=200, # Boosted estimators
                learning_rate=0.1,
                max_depth=7,      # Deeper trees
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                verbose=1
            )
            
            logger.info("Training Gradient Boosting Classifier (Boosted)...")
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            logger.info(f"\nModel accuracy: {accuracy:.4f}")
            logger.info("\nClassification Report:")
            logger.info(classification_report(y_test, y_pred, 
                                            target_names=self.label_encoder.classes_))
            
            if save_model:
                self.save_model()
                
            return accuracy
            
        except Exception as e:
            logger.error(f"Error training from JSON: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 0.0

    def load_iot23_dataset(self, dataset_dir: str) -> Tuple[np.ndarray, np.ndarray]:
        """Load IoT-23 dataset and aggregate by IP to match scan format"""
        dataset_dir = self.convert_windows_path(dataset_dir)
        if not os.path.exists(dataset_dir):
            logger.error(f"Dataset directory does not exist: {dataset_dir}")
            return np.array([]), np.array([])
        
        logger.info(f"Loading IoT-23 dataset from: {dataset_dir}")
        
        # Find all conn.log.labeled files
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
        all_labels = []
        
        # We need to aggregate by IP to simulate "scans"
        # Map: IP -> {ports: set(), services: set(), labels: list()}
        device_aggregation = {}
        
        for i, conn_file in enumerate(conn_files):
            logger.info(f"[{i+1}/{len(conn_files)}] Processing: {os.path.basename(conn_file)}")
            try:
                df = self.parse_conn_log_labeled(conn_file)
                if df.empty: continue
                
                # Limit rows to speed up processing if needed, but for "large dataset" request we should try to use more
                if len(df) > 50000:
                    df = df.sample(n=50000, random_state=42)
                
                # Group by Origin IP (Infected Device) and Responder IP (Target/Server)
                # In IoT-23, the labeled device is usually the Originator of malicious traffic, 
                # or the Responder if it's being attacked/scanned.
                # The 'label' column applies to the flow.
                
                for _, row in df.iterrows():
                    # We focus on the 'id.orig_h' as the device being profiled (Source of traffic)
                    # AND 'id.resp_h' as the device being profiled (Destination of traffic)
                    # This is tricky. Let's assume the "Scenario" defines the device IP.
                    # Since we don't know which IP is the device, we collect data for both ends 
                    # but only keep those that have meaningful labels.
                    
                    label = row.get('label', 'Benign')
                    if 'Benign' in label:
                        device_type = 'Benign'
                    else:
                        # Extract malware/attack type from label
                        device_type = label.split('   ')[0].strip() # Simple parsing
                    
                    # 1. Source IP (The device initiating connections)
                    src_ip = row.get('id.orig_h')
                    dst_port = row.get('id.resp_p')
                    proto = row.get('proto')
                    service = row.get('service')
                    
                    if src_ip not in device_aggregation:
                        device_aggregation[src_ip] = {'ports': set(), 'services': set(), 'labels': [], 'vendor': ''}
                    
                    # For source device, 'dst_port' is a port it talks TO. 
                    # This isn't an "open port" on the device.
                    # However, Nmap scans find OPEN ports (Responder ports).
                    
                    # 2. Dest IP (The device receiving connections)
                    dst_ip = row.get('id.resp_h')
                    if dst_ip not in device_aggregation:
                        device_aggregation[dst_ip] = {'ports': set(), 'services': set(), 'labels': [], 'vendor': ''}
                    
                    # The Dest IP has 'dst_port' OPEN.
                    if dst_port:
                        try:
                            device_aggregation[dst_ip]['ports'].add(int(dst_port))
                        except:
                            pass
                    
                    if service and service != '-':
                        device_aggregation[dst_ip]['services'].add(service)
                    
                    # Assign label to both? Usually the dataset is about a specific infected device.
                    # We will filter later by "interesting" devices (those with open ports/services)
                    device_aggregation[dst_ip]['labels'].append(device_type)
                    device_aggregation[src_ip]['labels'].append(device_type)

            except Exception as e:
                logger.error(f"Error reading {conn_file}: {e}")
                continue
                
        # Convert aggregated data to features
        logger.info(f"Aggregated data for {len(device_aggregation)} IPs. Extracting features...")
        
        count = 0
        for ip, data in device_aggregation.items():
            if not data['ports'] and not data['services']:
                continue
                
            # Determine dominant label
            if not data['labels']:
                final_label = 'Unknown'
            else:
                from collections import Counter
                # If any malicious label exists, mark as Malicious/Specific Malware
                # OR use majority vote. Let's use majority vote for Device Type Classification?
                # Actually, User wants Device Fingerprinting. IoT-23 is mostly Malware.
                # But it has "Benign" captures of IoT devices (Echo, Somfy, etc.)
                # We should try to extract the device name from the folder path if possible, but here we only have logs.
                # Let's rely on the label column.
                counts = Counter(data['labels'])
                final_label = counts.most_common(1)[0][0]
            
            # Construct Inputs for Feature Extractor
            device_info = {
                'vendor': '', # Unknown in raw logs
                'ttl': 64,    # Default
                'response_time': 0,
                'server_header': '',
                'ports': list(data['ports']),
                'services': list(data['services']),
                'mac': ''
            }
            
            nmap_results = {
                'ports': [{'port': p} for p in data['ports']],
                'services': {s: {} for s in data['services']}
            }
            
            features = self.extract_features_from_scans(device_info, nmap_results, {})
            all_features.append(features)
            all_labels.append(final_label)
            count += 1
            
        logger.info(f"Extracted features for {count} devices/IPs")
        
        if not all_features:
            return np.array([]), np.array([])
            
        return np.array(all_features), np.array(all_labels)

    def train_from_iot23_directory(self, dataset_dir: str, save_model: bool = True, 
                                 test_size: float = 0.2) -> float:
        """Train model from IoT-23 dataset directory AND synthetic data"""
        # 1. Load IoT-23 Data
        X_iot, y_iot = self.load_iot23_dataset(dataset_dir)
        
        # 2. Load Synthetic Data (if available)
        synthetic_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "synthetic_iot_data.json")
        X_syn = []
        y_syn = []
        
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
                        'mac': ''
                    }
                    nmap_results = {
                        'ports': [{'port': p} for p in item.get('ports', [])],
                        'services': {s: {} for s in item.get('services', [])}
                    }
                    features = self.extract_features_from_scans(device_info, nmap_results, {})
                    X_syn.append(features)
                    y_syn.append(item.get('device_type', 'Unknown'))
                    
                X_syn = np.array(X_syn)
                y_syn = np.array(y_syn)
                logger.info(f"Loaded {len(X_syn)} synthetic samples")
                
            except Exception as e:
                logger.error(f"Failed to load synthetic data: {e}")
        
        # 3. Merge Datasets
        if len(X_iot) > 0 and len(X_syn) > 0:
            X = np.concatenate((X_iot, X_syn), axis=0)
            y = np.concatenate((y_iot, y_syn), axis=0)
        elif len(X_iot) > 0:
            X, y = X_iot, y_iot
        elif len(X_syn) > 0:
            X, y = X_syn, y_syn
        else:
            logger.error("No data available for training (neither IoT-23 nor Synthetic)")
            return 0.0

        logger.info(f"Combined Dataset: {X.shape[0]} samples, {len(np.unique(y))} classes")
        
        # 4. Training Pipeline
        self.label_encoder.fit(y)
        y_encoded = self.label_encoder.transform(y)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=42, stratify=y_encoded
        )
        
        logger.info(f"Training set: {X_train.shape}, Test set: {X_test.shape}")
        
        self.scaler.fit(X_train)
        X_train_scaled = self.scaler.transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        self.model = GradientBoostingClassifier(
            n_estimators=200, # Increased for larger dataset
            learning_rate=0.1,
            max_depth=7,      # Increased depth
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            verbose=1
        )
        
        logger.info("Training Gradient Boosting Classifier (Combined)...")
        self.model.fit(X_train_scaled, y_train)
        
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        logger.info(f"\nModel accuracy: {accuracy:.4f}")
        logger.info("\nClassification Report:")
        # Handle cases where some classes in encoder might not be in test set
        try:
            logger.info(classification_report(y_test, y_pred, 
                                            target_names=self.label_encoder.classes_))
        except:
             logger.info(classification_report(y_test, y_pred))

        if save_model:
            self.save_model()
            
        return accuracy
    def classify_device(self, device_info: Dict, nmap_results: Dict, 
                       enhanced_scans: Dict) -> Tuple[str, float, Dict]:
        """Classify device using ML model"""
        try:
            features = self.extract_features_from_scans(
                device_info, nmap_results, enhanced_scans
            )
            if self.model is None or len(features) == 0:
                logger.warning("Model not available or features empty, using fallback")
                return self.fallback_classification(device_info, nmap_results)
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            if features.shape[1] != self.EXPECTED_FEATURES:
                logger.warning(f"Features shape mismatch: got {features.shape[1]}, expected {self.EXPECTED_FEATURES}")
                return self.fallback_classification(device_info, nmap_results)
            features_scaled = self.scaler.transform(features)
            prediction = self.model.predict(features_scaled)[0]
            probabilities = self.model.predict_proba(features_scaled)[0]
            if hasattr(self.label_encoder, 'classes_'):
                try:
                    class_name = self.label_encoder.inverse_transform([prediction])[0]
                except:
                    class_name = str(prediction)
            else:
                class_name = str(prediction)
            confidence = float(probabilities[prediction])
            top_predictions = []
            if len(probabilities) > 1:
                top_indices = np.argsort(probabilities)[-3:][::-1]
                for idx in top_indices:
                    if hasattr(self.label_encoder, 'classes_') and idx < len(self.label_encoder.classes_):
                        pred_class = self.label_encoder.classes_[idx]
                    else:
                        pred_class = str(idx)
                    top_predictions.append({
                        'class': pred_class,
                        'confidence': float(probabilities[idx])
                    })
            result = {
                'device_type': class_name,
                'confidence': confidence,
                'ml_model': 'GradientBoosting',
                'top_predictions': top_predictions,
                'features_used': features.shape[1],
                'feature_count': self.EXPECTED_FEATURES
            }

            # Prioritize Fallback "Router" or "Computer" if ML is unsure
            fallback_class, fallback_conf, _ = self.fallback_classification(device_info, nmap_results)
            
            # If ML returns a generic/unknown type, but fallback has a strong opinion (Router/Computer), use fallback
            if class_name in ['Benign_Device', 'Generic_Device', 'Unknown', 'Linux_Device', 'Metasploitable']:
                if fallback_class in ['Router', 'Computer']:
                    logger.info(f"Overriding ML classification {class_name} with Fallback {fallback_class}")
                    return fallback_class, fallback_conf, result

            logger.info(f"AI classification: {class_name} (confidence: {confidence:.2f})")
            return class_name, confidence, result
        except Exception as e:
            logger.error(f"AI classification failed: {e}")
            return self.fallback_classification(device_info, nmap_results)
    def extract_features_from_scans(self, device_info: Dict, nmap_results: Dict, 
                                   enhanced_scans: Dict) -> np.ndarray:
        """Extract features from scan data - FIXED to 25 features"""
        features = []
        try:
            ports = [p.get('port', 0) for p in nmap_results.get('ports', [])]
            features.append(float(len(ports)))
            iot_ports = {1883, 8883, 5683, 1900, 5353, 7547, 5555, 6667, 23, 2323, 80, 443, 22}
            iot_port_count = len(set(ports).intersection(iot_ports))
            features.append(float(iot_port_count))
            services = nmap_results.get('services', {})
            service_indicators = ['http', 'ssh', 'telnet', 'ftp', 'mqtt', 'coap', 'upnp']
            for svc in service_indicators:
                has_service = any(svc in name.lower() for name in services.keys())
                features.append(float(has_service))
            if enhanced_scans:
                iot_protocols = enhanced_scans.get('iot_protocols', {})
                for proto in ['mqtt', 'coap', 'upnp']:
                    features.append(float(proto in iot_protocols))
            else:
                features.extend([0.0, 0.0, 0.0])
            vendor = device_info.get('vendor', '').lower()
            vendor_keywords = ['iot', 'esp', 'raspberry', 'arduino', 'camera', 'router', 'smart']
            for keyword in vendor_keywords:
                features.append(float(keyword in vendor))
            mac = device_info.get('mac', '').lower()
            features.append(float(len(mac) > 0))  
            features.append(float('unknown' not in mac))  
            well_known_ports = len([p for p in ports if 0 < p < 1024])
            registered_ports = len([p for p in ports if 1024 <= p < 49151])
            dynamic_ports = len([p for p in ports if p >= 49151])
            features.extend([
                float(well_known_ports),
                float(registered_ports),
                float(dynamic_ports),
                float('https' in str(services).lower())  
            ])
            
            # NEW FEATURES (Total 30)
            ttl = float(device_info.get('ttl', 64))
            features.append(ttl)
            
            resp_time = float(device_info.get('response_time', 0))
            features.append(resp_time)
            
            server_header = device_info.get('server_header', '').lower()
            features.append(float(len(server_header)))
            features.append(float('nginx' in server_header))
            features.append(float('apache' in server_header))
            
        except Exception as e:
            logger.error(f"Error extracting features from scans: {e}")
            return np.zeros(self.EXPECTED_FEATURES)
        if len(features) < self.EXPECTED_FEATURES:
            features.extend([0.0] * (self.EXPECTED_FEATURES - len(features)))
        elif len(features) > self.EXPECTED_FEATURES:
            features = features[:self.EXPECTED_FEATURES]
        return np.array(features)
    def fallback_classification(self, device_info: Dict, nmap_results: Dict) -> Tuple[str, float, Dict]:
        """Fallback to rule-based classification"""
        vendor = device_info.get('vendor', '').lower()
        services = nmap_results.get('services', {})
        ports = [p.get('port', 0) for p in nmap_results.get('ports', [])]
        if 'raspberry' in vendor:
            return 'Raspberry_Pi', 0.8, {'method': 'vendor_match'}
        elif 'esp' in vendor or 'espressif' in vendor:
            return 'ESP_Device', 0.7, {'method': 'vendor_match'}
        elif any('mqtt' in s.lower() for s in services.keys()):
            return 'IoT_Device', 0.6, {'method': 'service_detection'}
        elif any('coap' in s.lower() for s in services.keys()):
            return 'IoT_Device', 0.6, {'method': 'service_detection'}
        elif any(p == 22 for p in ports) or any(p == 3389 for p in ports):
            return 'Computer', 0.7, {'method': 'port_detection'}
        elif any(p == 21 for p in ports):
            return 'Computer', 0.6, {'method': 'port_detection'}
        elif any('dns' in s.lower() or 'dhcp' in s.lower() for s in services.keys()) or 53 in ports:
            return 'Router', 0.8, {'method': 'service_detection'}
        elif any(p in [80, 443] for p in ports) and 53 in ports:
             return 'Router', 0.8, {'method': 'port_combination'}
        elif any('telnet' in s.lower() for s in services.keys()) or any(p == 23 for p in ports):
            return 'IoT_Device', 0.7, {'method': 'service_detection'}
        elif any(p in [80, 443] for p in ports):
            return 'Web_Server', 0.5, {'method': 'port_detection'}
        elif any(p == 22 for p in ports):
            return 'SSH_Server', 0.5, {'method': 'port_detection'}
        
        # Check for 0 ports
        if not ports and not services:
            return 'cant_determine', 0.1, {'method': 'no_ports'}

        return 'Generic_Device', 0.3, {'method': 'fallback'}
    def load_or_train_model(self):
        """Load existing model or initialize new one"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    saved_data = pickle.load(f)
                    self.model = saved_data['model']
                    self.scaler = saved_data['scaler']
                    self.label_encoder = saved_data['label_encoder']
                    logger.info(f" Loaded ML model from {self.model_path}")
                    if hasattr(self.model, 'n_estimators'):
                        logger.info(f"  Model type: {self.model.__class__.__name__}")
                        logger.info(f"  Estimators: {self.model.n_estimators}")
                        logger.info(f"  Classes: {len(self.label_encoder.classes_)}")
                    logger.info(f"  Expected features: {self.EXPECTED_FEATURES}")
            else:
                logger.warning(f"  Model file not found: {self.model_path}")
                logger.info("Will use fallback classification")
                self.model = None
        except Exception as e:
            logger.error(f" Error loading ML model: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.model = None
    def save_model(self):
        """Save the trained model"""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            saved_data = {
                'model': self.model,
                'scaler': self.scaler,
                'label_encoder': self.label_encoder,
                'timestamp': datetime.now().isoformat(),
                'classes': self.label_encoder.classes_.tolist() if hasattr(self.label_encoder, 'classes_') else [],
                'expected_features': self.EXPECTED_FEATURES
            }
            with open(self.model_path, 'wb') as f:
                pickle.dump(saved_data, f)
            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
