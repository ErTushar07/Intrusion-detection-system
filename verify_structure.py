#!/usr/bin/env python3
"""
Verify the project structure and imports without running the actual components
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def verify_imports():
    """Verify that all modules can be imported"""
    modules = [
        'ids.core.ids_engine',
        'ids.packet_capture.packet_sniffer',
        'ids.detection.signature_detector',
        'ids.detection.anomaly_detector',
        'ids.logging.alert_logger'
    ]
    
    success_count = 0
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module} - Import successful")
            success_count += 1
except (ModuleNotFoundError, ImportError) as e:
            print(f"X {module} - Import failed: {e}")    
    print(f"\nImport verification: {success_count}/{len(modules)} modules imported successfully")
    return success_count == len(modules)

def verify_file_structure():
    """Verify that all required files exist"""
    required_files = [
        'main.py',
        'requirements.txt',
        'ids/__init__.py',
        'ids/core/__init__.py',
        'ids/core/ids_engine.py',
        'ids/packet_capture/__init__.py',
        'ids/packet_capture/packet_sniffer.py',
        'ids/detection/__init__.py',
        'ids/detection/signature_detector.py',
        'ids/detection/anomaly_detector.py',
        'ids/logging/__init__.py',
        'ids/logging/alert_logger.py'
    ]
    
    success_count = 0
    for file_path in required_files:
        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), file_path)
        if os.path.exists(full_path):
            print(f"✓ {file_path} - File exists")
            success_count += 1
        else:
            print(f"✗ {file_path} - File missing")
    
    print(f"\nFile structure verification: {success_count}/{len(required_files)} files found")
    return success_count == len(required_files)

def main():
    """Main verification function"""
    print("Verifying IDS Project Structure\n")
    print("=" * 40)

    imports_ok = verify_imports()
    print()
    files_ok = verify_file_structure()

    print("\n" + "=" * 40)
    if imports_ok and files_ok:
        print("✓ All verifications passed! The project structure is complete.")
        print("\nTo run the IDS, you need to:")
        print("1. Install Python 3.6+")
        print("2. Install dependencies: pip install -r requirements.txt")
        print("3. Initialize the system: python initialize_ids.py")
        print("4. Run the IDS: python main.py")
    else:
        print("✗ Some verifications failed. Please check the errors above.")

if __name__ == "__main__":
    main()
