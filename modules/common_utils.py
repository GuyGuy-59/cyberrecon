"""
Shared helpers for CyberRecon modules: paths under ``result/``, timestamps, JSON I/O.
"""
import json
import os
import socket
import time

from .config import result

# Returned by module ``run()`` when the hostname cannot be resolved to an IPv4 address.
SKIP_RESOLUTION_FAILED = "skip_resolution"


def resolve_host_to_ip(hostname, logger):
    """Resolve a hostname to an IPv4 address; return the input if it is already IPv4."""
    try:
        return socket.gethostbyname(hostname.strip())
    except socket.gaierror as e:
        logger.warning("Could not resolve IP for %s: %s", hostname, e)
        return None


def scan_timestamp():
    """Short timestamp for scan metadata (minute precision)."""
    return time.strftime("%Y-%m-%d %H:%M")


def scan_timestamp_long():
    """Timestamp including seconds."""
    return time.strftime("%Y-%m-%d %H:%M:%S")


def base_scan_meta(target):
    """Common ``target`` + ``scan_date`` block for JSON exports."""
    return {"target": target, "scan_date": scan_timestamp()}


def base_scan_meta_long(target):
    """Same as ``base_scan_meta`` but with second-level timestamp in ``scan_date``."""
    return {"target": target, "scan_date": scan_timestamp_long()}


def result_path(*parts):
    """Path under the configured ``result`` directory."""
    return os.path.join(result, *parts)


def save_json_result(
    subject,
    basename,
    data,
    logger,
    description=None,
    *,
    indent=4,
    sort_keys=False,
):
    """Write ``data`` as UTF-8 JSON to ``results/<subject>/<basename>``."""
    desc = description or basename
    try:
        path = result_path(subject, basename)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, sort_keys=sort_keys)
        logger.info(f"{desc} saved to: {path}")
    except Exception as e:
        logger.error(f"Failed to save {desc}: {e}")


def save_json_file(path, data, logger, description=None, *, indent=4, sort_keys=False):
    """Write JSON to a full path; create parent directories if needed."""
    desc = description or path
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, sort_keys=sort_keys)
        logger.info(f"{desc} saved to: {path}")
    except Exception as e:
        logger.error(f"Failed to save {desc}: {e}")
