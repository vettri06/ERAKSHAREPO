NVD_API_KEY = "b9753cd1-8ade-4d21-bf7c-bca73900d1bc"
SCAN_CONFIG = {
    'default_timeout': 5,
    'max_ports': 100,
    'enable_nmap': True,
    'enable_passive': True,
    'ai_enabled': True,
    'routed_subnets': [
        '10.142.138.0/24'  # VMware bridged LAN
    ]
}
DEVICE_CLASSIFICATION = {
    'iot_devices': [
        'raspberry',
        'esp32',
        'esp8266',
        'arduino',
        'smart',
        'camera'
    ],
    'network_devices': [
        'router',
        'switch',
        'gateway',
        'firewall'
    ]
}
MAC_OUI_MAPPING = {
    '00:0c:29': 'VMware',
    '00:50:56': 'VMware',
    'b8:27:eb': 'Raspberry Pi',
    'a4:5e:60': 'Apple',
    '00:1e:65': 'Apple',
    'f4:39:30': 'Espressif',
    'a2:c1:cf': 'Espressif',
    '00:1b:2f': 'TP-Link',
    'c0:56:27': 'TP-Link',
    '00:24:be': 'Netgear',
    '00:1e:2a': 'ASUS',
    '00:26:f2': 'Belkin',
    '00:1d:60': 'D-Link',
    '00:1c:f0': 'Samsung',
    '00:23:15': 'Huawei'
}
AI_CONFIG = {
    "enable_ai_classification": True,
    "classification_confidence_threshold": 0.6,
    "enable_anomaly_detection": True,
    "anomaly_score_threshold": 0.75,
    "model_paths": {
        "classifier": "models/device_classifier.pkl",
        "anomaly": "models/anomaly_detector.pkl"
    },
    "training": {
        "auto_train": True,
        "min_samples": 50,
        "retrain_interval_days": 30
    }
}