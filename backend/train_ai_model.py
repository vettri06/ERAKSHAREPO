"""
Training script for AI models with IoT-23 dataset support
Optimized for Windows
"""
import json
import logging
import argparse
import os
import sys
import glob
from datetime import datetime
from typing import List, Dict
import numpy as np
import pandas as pd
from pathlib import Path, PureWindowsPath
try:
    from iot_security.ai_classifier import AIDeviceClassifier
    from iot_security.anomaly_detector import AnomalyDetector
except ImportError:
    print("Error: Could not import AI modules.")
    print("Make sure ai_classifier.py and anomaly_detector.py are in iot_security directory.")
    sys.exit(1)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
def convert_windows_path(path: str) -> str:
    """Convert Windows path to proper format"""
    return str(PureWindowsPath(path))
def find_iot23_datasets(base_dir: str) -> List[str]:
    """Find all IoT-23 dataset directories"""
    base_dir = convert_windows_path(base_dir)
    if not os.path.exists(base_dir):
        logger.error(f"Directory does not exist: {base_dir}")
        return []
    logger.info(f"Searching for IoT-23 datasets in: {base_dir}")
    datasets = []
    patterns = [
        os.path.join(base_dir, "**", "bro", "conn.log.labeled"),
        os.path.join(base_dir, "**", "conn.log.labeled"),
        os.path.join(base_dir, "**", "*.log")
    ]
    all_conn_files = []
    for pattern in patterns:
        files = glob.glob(pattern, recursive=True)
        all_conn_files.extend(files)
    all_conn_files = list(set(all_conn_files))
    logger.info(f"Found {len(all_conn_files)} conn.log files")
    dataset_map = {}
    for conn_file in all_conn_files:
        if "bro" in conn_file:
            dataset_dir = os.path.dirname(os.path.dirname(conn_file))
        else:
            dataset_dir = os.path.dirname(conn_file)
        if dataset_dir not in dataset_map:
            dataset_map[dataset_dir] = []
        dataset_map[dataset_dir].append(conn_file)
    for dataset_dir, conn_files in dataset_map.items():
        dataset_name = os.path.basename(dataset_dir)
        logger.info(f"Dataset: {dataset_name} ({len(conn_files)} log files)")
        datasets.append(dataset_dir)
    logger.info(f"Total datasets found: {len(datasets)}")
    return datasets
def analyze_dataset(dataset_dir: str):
    """Analyze dataset structure and contents"""
    dataset_dir = convert_windows_path(dataset_dir)
    logger.info(f"\nAnalyzing dataset: {dataset_dir}")
    patterns = [
        os.path.join(dataset_dir, "**", "bro", "conn.log.labeled"),
        os.path.join(dataset_dir, "**", "conn.log.labeled")
    ]
    conn_files = []
    for pattern in patterns:
        files = glob.glob(pattern, recursive=True)
        conn_files.extend(files)
    if not conn_files:
        logger.warning("No conn.log files found")
        return
    logger.info(f"Found {len(conn_files)} conn.log files")
    for i, conn_file in enumerate(conn_files[:3]):
        logger.info(f"\nAnalyzing file {i+1}: {os.path.basename(conn_file)}")
        try:
            with open(conn_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = []
                header_lines = []
                for j, line in enumerate(f):
                    if j >= 100:  
                        break
                    if line.startswith('#'):
                        header_lines.append(line.strip())
                    else:
                        lines.append(line.strip())
            if lines:
                sample_line = lines[0]
                parts = sample_line.split('\t')
                logger.info(f"  Sample line has {len(parts)} columns")
                logger.info(f"  First few columns: {parts[:5]}")
                if len(parts) > 20:
                    label = parts[-2] if len(parts) > 21 else parts[-1]
                    logger.info(f"  Label column: {label}")
            logger.info(f"  Total lines: {len(lines) + len(header_lines)}")
            logger.info(f"  Header lines: {len(header_lines)}")
            logger.info(f"  Data lines: {len(lines)}")
        except Exception as e:
            logger.error(f"Error analyzing {conn_file}: {e}")
def train_classifier(dataset_dir: str, output_model: str = None):
    """Train device classifier"""
    logger.info("\n" + "=" * 70)
    logger.info("TRAINING DEVICE CLASSIFIER")
    logger.info("=" * 70)
    if output_model is None:
        output_model = os.path.join("models", "device_classifier_iot23.pkl")
    classifier = AIDeviceClassifier(model_path=output_model)
    logger.info(f"Dataset directory: {dataset_dir}")
    logger.info(f"Output model: {output_model}")
    try:
        accuracy = classifier.train_from_iot23_directory(dataset_dir)
        if accuracy > 0:
            logger.info(f" SUCCESS: Classifier trained with accuracy: {accuracy:.4f}")
            logger.info(f"   Model saved to: {classifier.model_path}")
        else:
            logger.error(" FAILED: Classifier training failed")
        return accuracy
    except Exception as e:
        logger.error(f" ERROR during training: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return 0.0
def train_anomaly_detector(dataset_dir: str, output_model: str = None):
    """Train anomaly detector"""
    logger.info("\n" + "=" * 70)
    logger.info("TRAINING ANOMALY DETECTOR")
    logger.info("=" * 70)
    if output_model is None:
        output_model = os.path.join("models", "anomaly_detector_iot23.pkl")
    detector = AnomalyDetector(model_path=output_model)
    logger.info(f"Dataset directory: {dataset_dir}")
    logger.info(f"Output model: {output_model}")
    try:
        detector.train_from_iot23_directory(dataset_dir)
        logger.info(" SUCCESS: Anomaly detector trained")
        logger.info(f"   Model saved to: {detector.model_path}")
        return True
    except Exception as e:
        logger.error(f" ERROR during training: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
def main():
    parser = argparse.ArgumentParser(
        description='Train AI models for IoT Security Scanner with IoT-23 Dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Find datasets in your directory
  python train_ai_model.py --find --dir "C:\\Users\\vv\\Desktop\\bla\\iot_23_datasets_small"
  # Analyze dataset structure
  python train_ai_model.py --analyze --dir "C:\\Users\\vv\\Desktop\\bla\\iot_23_datasets_small"
  # Train both models
  python train_ai_model.py --all --dir "C:\\Users\\vv\\Desktop\\bla\\iot_23_datasets_small"
  # Train only classifier
  python train_ai_model.py --classifier --dir "C:\\Users\\vv\\Desktop\\bla\\iot_23_datasets_small"
  # Train only anomaly detector
  python train_ai_model.py --anomaly --dir "C:\\Users\\vv\\Desktop\\bla\\iot_23_datasets_small"
        """
    )
    parser.add_argument('--classifier', action='store_true', 
                       help='Train device classifier')
    parser.add_argument('--anomaly', action='store_true', 
                       help='Train anomaly detector')
    parser.add_argument('--all', action='store_true', 
                       help='Train all models')
    parser.add_argument('--dir', '--dataset-dir', type=str, 
                       default="C:\\Users\\vv\\Desktop\\bla\\iot_23_datasets_small",
                       help='Path to IoT-23 datasets directory')
    parser.add_argument('--output', type=str, default='models', 
                       help='Output directory for models')
    parser.add_argument('--find', '--find-datasets', action='store_true', 
                       help='Find IoT-23 datasets in directory')
    parser.add_argument('--analyze', action='store_true', 
                       help='Analyze dataset without training')
    args = parser.parse_args()
    if args.all:
        args.classifier = True
        args.anomaly = True
    dataset_dir = convert_windows_path(args.dir)
    os.makedirs(args.output, exist_ok=True)
    logger.info("=" * 70)
    logger.info("IOT-23 AI MODEL TRAINER")
    logger.info("=" * 70)
    logger.info(f"Start time: {datetime.now()}")
    logger.info(f"Dataset directory: {dataset_dir}")
    logger.info(f"Output directory: {args.output}")
    if not os.path.exists(dataset_dir):
        logger.error(f" Dataset directory does not exist: {dataset_dir}")
        logger.info(f"Please check the path and try again.")
        return
    if args.find:
        logger.info("\n" + "=" * 70)
        logger.info("FINDING IOT-23 DATASETS")
        logger.info("=" * 70)
        datasets = find_iot23_datasets(dataset_dir)
        if not datasets:
            logger.warning("No IoT-23 datasets found!")
            logger.info("\nCheck if your directory contains files like:")
            logger.info("  CTU-IoT-Malware-Capture-XX-X/bro/conn.log.labeled")
            logger.info("\nCommon issues:")
            logger.info("  1. Wrong directory path")
            logger.info("  2. Dataset files not downloaded")
            logger.info("  3. File permissions")
        else:
            logger.info(f"\n Found {len(datasets)} datasets")
            for i, ds in enumerate(datasets[:10], 1):
                logger.info(f"{i}. {os.path.basename(ds)}")
            if len(datasets) > 10:
                logger.info(f"... and {len(datasets) - 10} more")
        return
    if args.analyze:
        logger.info("\n" + "=" * 70)
        logger.info("DATASET ANALYSIS")
        logger.info("=" * 70)
        analyze_dataset(dataset_dir)
        return
    classifier_acc = 0.0
    anomaly_trained = False
    if args.classifier:
        classifier_model = os.path.join(args.output, "device_classifier_iot23.pkl")
        classifier_acc = train_classifier(dataset_dir, classifier_model)
    if args.anomaly:
        anomaly_model = os.path.join(args.output, "anomaly_detector_iot23.pkl")
        anomaly_trained = train_anomaly_detector(dataset_dir, anomaly_model)
    generate_training_report(classifier_acc, anomaly_trained, dataset_dir)
    if not any([args.classifier, args.anomaly, args.all, args.find, args.analyze]):
        parser.print_help()
def generate_training_report(classifier_acc: float, anomaly_trained: bool, dataset_dir: str):
    """Generate training report"""
    logger.info("\n" + "=" * 70)
    logger.info("TRAINING COMPLETE - SUMMARY REPORT")
    logger.info("=" * 70)
    dataset_name = os.path.basename(dataset_dir)
    logger.info(f"Dataset: {dataset_name}")
    logger.info(f"Location: {dataset_dir}")
    logger.info("\nModel Status:")
    logger.info("-" * 40)
    if classifier_acc > 0:
        logger.info(f" Device Classifier: ACCURACY = {classifier_acc:.4f}")
        logger.info(f"  Model file: models/device_classifier_iot23.pkl")
    else:
        logger.info(" Device Classifier: NOT TRAINED")
    if anomaly_trained:
        logger.info(" Anomaly Detector: TRAINED")
        logger.info(f"  Model file: models/anomaly_detector_iot23.pkl")
    else:
        logger.info(" Anomaly Detector: NOT TRAINED")
    logger.info("\nNext Steps:")
    logger.info("-" * 40)
    logger.info("1. Use the trained models in IoT Security Scanner:")
    logger.info("   python iot_scanner.py")
    logger.info("\n2. For quick scan with AI:")
    logger.info("   python iot_scanner.py 3")
    logger.info("\n3. Check training logs:")
    logger.info("   - ai_training.log (training details)")
    logger.info("   - iot_scanner.log (scan results)")
    logger.info("\n4. Model files location:")
    logger.info("   - models/device_classifier_iot23.pkl")
    logger.info("   - models/anomaly_detector_iot23.pkl")
    logger.info("\n" + "=" * 70)
    logger.info(f"Training completed at: {datetime.now()}")
    logger.info("=" * 70)
if __name__ == "__main__":
    main()