"""
Setup script for AI features
"""
import os
import subprocess
import sys
def install_dependencies():
    """Install AI/ML dependencies"""
    print("Installing AI/ML dependencies...")
    dependencies = [
        'scikit-learn>=1.3.0',
        'numpy>=1.24.0',
        'pandas>=2.0.0',
        'joblib>=1.2.0'
    ]
    for dep in dependencies:
        print(f"  Installing {dep}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
    print(" AI dependencies installed")
def create_directories():
    """Create necessary directories"""
    directories = [
        'models',
        'training_data',
        'logs'
    ]
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f" Created directory: {directory}")
        else:
            print(f" Directory exists: {directory}")
def download_pretrained_models():
    """Download pretrained models if available"""
    print("\nAI Model Setup:")
    print("1. Models will be trained on first use")
    print("2. You can also train manually: python iot_scanner.py --train-ai")
    print("3. Or use: python train_ai_model.py --all")
def main():
    """Main setup function"""
    print("=" * 60)
    print("IoT Security Scanner - AI Features Setup")
    print("=" * 60)
    try:
        create_directories()
        install_dependencies()
        download_pretrained_models()
        print("\n" + "=" * 60)
        print(" AI setup complete!")
        print("\nNext steps:")
        print("1. Run: python iot_scanner.py --train-ai")
        print("2. Or run a scan: python iot_scanner.py")
        print("=" * 60)
    except Exception as e:
        print(f"\n Setup failed: {e}")
        print("\nManual installation:")
        print("pip install scikit-learn numpy pandas joblib")
        sys.exit(1)
if __name__ == "__main__":
    main()