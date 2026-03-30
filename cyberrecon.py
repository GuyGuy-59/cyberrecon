#!/usr/bin/env python3
"""
CyberRecon OSINT Tool - Main Script
Automated OSINT tool for comprehensive security analysis
"""

import sys
import os
import json
import argparse
import logging
import socket
from modules.config import *

_MODULES_MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules.json")
_MODULES_MANIFEST_CACHE = None


def _load_modules_manifest():
    """Load and cache modules.json (definitions + list-modules categories)."""
    global _MODULES_MANIFEST_CACHE
    if _MODULES_MANIFEST_CACHE is None:
        with open(_MODULES_MANIFEST_PATH, encoding="utf-8") as f:
            _MODULES_MANIFEST_CACHE = json.load(f)
    return _MODULES_MANIFEST_CACHE

def setup_logging(target=None):
    """Setup logging configuration"""
    os.makedirs(result, exist_ok=True)

    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Create file handler with UTF-8 encoding
    if target:
        # Create target-specific log file
        log_filename = f'cyberrecon_{target.replace(".", "_").replace("/", "_")}.log'
        file_handler = logging.FileHandler(f'{result}{log_filename}', encoding='utf-8')
    else:
        # Fallback to general log file
        file_handler = logging.FileHandler(f'{result}cyberrecon.log', encoding='utf-8')
    
    file_handler.setFormatter(formatter)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Setup logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def run_configuration_check():
    """Run configuration check before starting the scan"""
    try:
        from modules.config_checker import check_configuration
        print("=== Running Configuration Check ===")
        result = check_configuration()
        
        if result > 1:
            print("\n❌ Critical configuration issues found. Please fix them before running CyberRecon.")
            return False
        elif result == 1:
            print("\n⚠️  Some configuration issues found. Some modules may not work optimally.")
            response = input("Do you want to continue? (y/N): ").lower().strip()
            if response not in ['y', 'yes']:
                return False
        else:
            print("\n✅ Configuration check passed!")
        
        return True
    except Exception as e:
        print(f"⚠️  Configuration check failed: {e}")
        response = input("Do you want to continue anyway? (y/N): ").lower().strip()
        return response in ['y', 'yes']

def get_available_modules():
    """Get list of available modules from modules.json."""
    data = _load_modules_manifest()
    out = {}
    for key, spec in data["modules"].items():
        out[key] = (spec["display_name"], spec["package"], spec["function"])
    return out


def get_module_list_categories():
    """
    Categories and one-line descriptions for --list-modules.
    Order matches logical grouping; every key from get_available_modules() must appear once.
    """
    data = _load_modules_manifest()
    result = []
    for cat in data["categories"]:
        items = [(item["id"], item["description"]) for item in cat["items"]]
        result.append((cat["name"], items))
    return result


def print_modules_list():
    """Print modules grouped by category: category title, then [*] name + description."""
    available = get_available_modules()
    categories = get_module_list_categories()

    listed = []
    for _, items in categories:
        listed.extend(k for k, _ in items)

    missing = set(available.keys()) - set(listed)
    extra = set(listed) - set(available.keys())
    if missing or extra:
        raise RuntimeError(
            f"modules.json categories out of sync with modules: missing={missing!r} extra={extra!r}"
        )

    name_width = 0
    for _, items in categories:
        for key, _ in items:
            name_width = max(name_width, len(key))
    name_width = max(name_width + 2, 26)

    for idx, (cat, items) in enumerate(categories):
        print(cat)
        for key, desc in items:
            print(f"[*] {key:<{name_width}}{desc}")
        if idx < len(categories) - 1:
            print()

def run_modules(target, selected_modules, logger):
    """Run selected modules on the target"""
    available_modules = get_available_modules()
    
    # If no modules specified, run all
    if not selected_modules:
        selected_modules = list(available_modules.keys())
    
    # Validate selected modules
    invalid_modules = [m for m in selected_modules if m not in available_modules]
    if invalid_modules:
        print(f"❌ Invalid modules: {', '.join(invalid_modules)}")
        print(f"Available modules: {', '.join(available_modules.keys())}")
        return []
    
    results = []
    
    for module_key in selected_modules:
        name, module_name, function_name = available_modules[module_key]
        
        try:
            logger.info(f"Starting {name} analysis...")
            module = __import__(module_name, fromlist=[function_name])
            function = getattr(module, function_name)
            
            # Special handling for functions that need different parameters
            if function_name == "scan_victim":
                try:
                    target_ip = socket.gethostbyname(target)
                    function(target, target_ip, logger)
                except socket.gaierror:
                    logger.warning(f"Could not resolve IP for {target}, skipping scan")
                    results.append((name, "⚠ Skipped (IP resolution failed)"))
                    continue
            elif function_name == "scan_robots":
                function(target, f"https://{target}", logger)
            elif function_name == "device_shodan":
                # Try to get IP for Shodan
                try:
                    target_ip = socket.gethostbyname(target)
                    function(target, target_ip, logger)
                except socket.gaierror:
                    logger.warning(f"Could not resolve IP for {target}, skipping Shodan")
                    results.append((name, "⚠ Skipped (IP resolution failed)"))
                    continue
            else:
                function(target, logger)
            
            results.append((name, "✓ Completed"))
            logger.info(f"✓ {name} analysis completed")
            
        except Exception as e:
            results.append((name, f"✗ Failed: {e}"))
            logger.error(f"✗ {name} analysis failed: {e}")
    
    return results

def main():
    module_ids = list(get_available_modules().keys())
    parser = argparse.ArgumentParser(description="CyberRecon OSINT Tool")
    parser.add_argument('target', nargs='?', help='Target domain or IP to analyze')
    parser.add_argument('--modules', '-m', nargs='+',
                       choices=module_ids,
                       help='Specific modules to run (default: all modules)')
    parser.add_argument('--list-modules', '-L', action='store_true',
                       help='List available modules and exit')
    parser.add_argument('--skip-config-check', action='store_true',
                       help='Skip configuration check before running')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # List available modules if requested
    if args.list_modules:
        print_modules_list()
        return 0
    
    # Check if target is provided
    if not args.target:
        parser.error("target is required unless using --list-modules")
    
    print("=== CyberRecon OSINT Tool ===")
    print(f"Target: {args.target}")
    
    # Display selected modules
    if args.modules:
        print(f"Modules: {', '.join(args.modules)}")
    else:
        print("Modules: All available modules")
    
    print("="*50)
    
    # Setup logging
    logger = setup_logging(args.target)
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Run configuration check
    if not args.skip_config_check:
        if not run_configuration_check():
            print("Exiting due to configuration issues.")
            return 1
        print()
    
    # Run selected modules
    print(f"Starting analysis of {args.target}...")
    print()
    
    results = run_modules(args.target, args.modules, logger)
    
    if not results:
        print("❌ No modules were executed successfully.")
        return 2
    
    # Display summary
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    
    for name, status in results:
        print(f"{status} {name}")
    
    completed = sum(1 for _, status in results if status.startswith("✓"))
    skipped = sum(1 for _, status in results if status.startswith("⚠"))
    failed = sum(1 for _, status in results if status.startswith("✗"))
    total = len(results)
    
    print(f"\nTotal: {completed} completed, {skipped} skipped, {failed} failed")
    
    if completed == total:
        print("🎉 All modules completed successfully!")
        return 0
    elif completed >= total * 0.8:
        print("⚠️  Most modules completed successfully. Check logs for details.")
        return 1
    else:
        print("❌ Several modules failed. Check logs for details.")
        return 2

if __name__ == '__main__':
    sys.exit(main())