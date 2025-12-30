import sys
import os
import importlib

def check_import(module_name):
    try:
        importlib.import_module(module_name)
        print(f"[OK] Module '{module_name}' imported successfully.")
        return True
    except ImportError as e:
        print(f"[FAIL] Module '{module_name}' could not be imported: {e}")
        return False

def check_file(path):
    if os.path.exists(path):
        print(f"[OK] File '{path}' exists.")
        return True
    else:
        print(f"[FAIL] File '{path}' is MISSING.")
        return False

def main():
    print("Starting Backend Integrity Check...")
    
    # 1. Check Dependencies
    dependencies = [
        'fastapi', 'uvicorn', 'pydantic', 'scapy', 
        'sklearn', 'pandas', 'numpy', 'psutil', 
        'requests', 'mac_vendor_lookup', 'nmap'
    ]
    
    all_deps_ok = True
    for dep in dependencies:
        if not check_import(dep):
            all_deps_ok = False
            
    # 2. Check Model Files
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    model_files = [
        'anomaly_detector_iot23.pkl',
        'device_classifier_iot23.pkl'
    ]
    
    all_models_ok = True
    for model in model_files:
        if not check_file(os.path.join(models_dir, model)):
            all_models_ok = False
            
    # 3. Check Nmap Binary (System check)
    import shutil
    if shutil.which('nmap'):
        print("[OK] Nmap binary found in system PATH.")
    else:
        print("[WARNING] Nmap binary NOT found in system PATH. Scans may fail.")

    if all_deps_ok and all_models_ok:
        print("\nSUCCESS: Backend integrity check passed (with possible warnings).")
        sys.exit(0)
    else:
        print("\nFAILURE: Backend integrity check failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
