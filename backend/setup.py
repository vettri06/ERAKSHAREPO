from setuptools import setup, find_packages
setup(
    name="iot-security-scanner-ai",
    version="3.0.0",
    packages=find_packages(),
    install_requires=[
        'scikit-learn>=1.3.0',
        'numpy>=1.24.0',
        'pandas>=2.0.0',
        'joblib>=1.2.0',
        'scapy>=2.5.0',
        'psutil>=5.9.0',
        'requests>=2.28.0',
        'mac-vendor-lookup>=0.1.11',
        'python-nmap>=0.7.1',
    ],
    entry_points={
        'console_scripts': [
            'iot-scanner=iot_security.iot_scanner:main',
            'train-ai-models=iot_security.train_ai_model:main',
        ],
    },
    author="IoT Security Team",
    description="AI-enhanced IoT Security Scanner with ML classification and anomaly detection",
    keywords="iot security scanner ai ml network scanning",
    python_requires='>=3.8',
)