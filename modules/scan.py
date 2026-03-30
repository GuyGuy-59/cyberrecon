import os
import nmap3
import json
import time
import logging
from .config import *
from .common_utils import (
    SKIP_RESOLUTION_FAILED,
    base_scan_meta_long,
    resolve_host_to_ip,
    result_path,
    save_json_file,
)


def read_json_from_file(directory, filename):
    """Read data from JSON file with error handling"""
    try:
        filepath = os.path.join(directory, filename)
        with open(filepath, "r") as file:
            return json.load(file)
    except Exception as e:
        logging.error(f"Error reading from {filename}: {e}")
        return None


def _write_json_and_verify(directory, filename, data, logger):
    """Write JSON then read back to confirm persistence."""
    filepath = os.path.join(directory, filename)
    save_json_file(filepath, data, logger, description=filename)
    if read_json_from_file(directory, filename) is None:
        logger.warning(f"Could not read back scan file {filename} for verification")


def perform_scan(scan_type, victim, victim_ip, nmap_instance, logger):
    """Perform nmap scan with enhanced error handling and progress tracking"""
    directory = result_path(victim, f"scan_{victim_ip}")
    logger.info(f"\n-- {scan_type} Scan for {victim_ip} --\n")
    
    try:
        start_time = time.time()
        results = nmap_instance(victim_ip)
        scan_duration = time.time() - start_time
        
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        
        filename = f"{scan_type}Scan_{victim_ip}.json"
        _write_json_and_verify(directory, filename, results, logger)

        summary = {
            **base_scan_meta_long(victim_ip),
            "scan_type": scan_type,
            "scan_duration": scan_duration,
            "results": results,
        }
        _write_json_and_verify(directory, f"{scan_type}Summary_{victim_ip}.json", summary, logger)
        
        return results
        
    except Exception as e:
        logger.error(f"Error during {scan_type} scan: {e}")
        return None

def log_scan_results(data, victim_ip, logger):
    """Enhanced logging of scan results with better formatting"""
    if not data or victim_ip not in data:
        logger.warning("No scan data available")
        return
    
    if "ports" not in data[victim_ip]:
        logger.info("No ports found in scan results")
        return
    
    tab_ports = data[victim_ip]["ports"]
    logger.info(f"\nFound {len(tab_ports)} open ports:")
    
    for port_info in tab_ports:
        results_json = {
            "Port": port_info.get('portid', 'Unknown'),
            "Protocol": port_info.get('protocol', 'Unknown'),
            "State": port_info.get('state', 'Unknown')
        }
        
        service = port_info.get('service') or {}
        if service:
            keys = ('name', 'product', 'version', 'extrainfo')
            results_json['service'] = {k: service[k] for k in keys if service.get(k)}
        
        # Log in a more readable format
        port_str = f"Port {results_json['Port']}/{results_json['Protocol']} - {results_json['State']}"
        if 'service' in results_json and results_json['service']:
            service_str = " | ".join([f"{k}: {v}" for k, v in results_json['service'].items()])
            port_str += f" | {service_str}"
        
        logger.info(f"  {port_str}")

def scan_victim(victim, victim_ip, logger):
    """Enhanced victim scanning with better error handling and progress tracking"""
    logger.info(f"Starting port scan for {victim} ({victim_ip})")
    
    try:
        # Initialize nmap instances
        nmap_ping = nmap3.NmapScanTechniques()
        nmap_full = nmap3.Nmap()
        
        # Perform ping scan first
        logger.info("Performing ping scan...")
        ping_data = perform_scan("ping", victim, victim_ip, nmap_ping.nmap_ping_scan, logger)
        
        if not ping_data or victim_ip not in ping_data:
            logger.error("Ping scan failed or no data returned")
            return
        
        state = ping_data[victim_ip].get("state", {}).get("state", "unknown")
        logger.info(f"{victim_ip} is {state}")
        
        if state == "up":
            logger.info("Host is up, performing full port scan...")
            full_scan_data = perform_scan("full", victim, victim_ip, nmap_full.nmap_version_detection, logger)
            
            if full_scan_data:
                log_scan_results(full_scan_data, victim_ip, logger)
            else:
                logger.error("Full scan failed")
        else:
            logger.warning(f"Host {victim_ip} is not responding to ping")
            
    except Exception as e:
        logger.error(f"Error during victim scan: {e}")


def run(victim, logger):
    """Entry point: resolve host to IPv4 then run ping + full nmap scans."""
    target_ip = resolve_host_to_ip(victim, logger)
    if not target_ip:
        return SKIP_RESOLUTION_FAILED
    scan_victim(victim, target_ip, logger)
