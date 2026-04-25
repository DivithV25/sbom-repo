import requests
import hashlib
import os
import json
from pathlib import Path
from agent.config_loader import get_config

# Cache directory and metadata file
CACHE_DIR = Path(".prism_cache")
CACHE_METADATA_FILE = CACHE_DIR / "cache_metadata.json"


def _parse_cvss_score(score_string):
    """Parse numeric CVSS base score from a vector string (e.g. CVSS:3.1/AV:N/...).
    Falls back to None if parsing fails."""
    if not score_string or not isinstance(score_string, str):
        return None
    # Already a plain number
    try:
        return float(score_string)
    except (ValueError, TypeError):
        pass
    # CVSS vector string — use the cvss library to compute the base score
    try:
        from cvss import CVSS3
        c = CVSS3(score_string)
        return float(c.base_score)
    except Exception:
        pass
    return None


def _get_dependency_file_hash():
    """Get SHA256 hash of current dependency manifest (package.json, requirements.txt, etc)."""
    # Check for npm
    if os.path.exists("package.json"):
        with open("package.json", "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    # Check for Python
    elif os.path.exists("requirements.txt"):
        with open("requirements.txt", "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    # Check for Maven
    elif os.path.exists("pom.xml"):
        with open("pom.xml", "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    # Check for Go
    elif os.path.exists("go.mod"):
        with open("go.mod", "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    
    return None


def _invalidate_cache_if_needed():
    """
    Invalidate cache if dependency manifest has changed.
    
    This prevents using stale vulnerability data when package versions change.
    Cache is automatically cleared when:
    - package.json, requirements.txt, pom.xml, or go.mod is modified
    - Cache metadata doesn't exist
    
    Cache metadata tracks the hash of the dependency file to detect changes.
    """
    current_hash = _get_dependency_file_hash()
    if current_hash is None:
        print("⚠️ No dependency manifest file found (package.json, requirements.txt, etc)")
        return
    
    # Check if cache metadata exists
    if CACHE_METADATA_FILE.exists():
        try:
            with open(CACHE_METADATA_FILE, "r") as f:
                metadata = json.load(f)
                cached_hash = metadata.get("dependency_manifest_hash")
                
            if cached_hash != current_hash:
                print("🔄 Dependency manifest changed - invalidating vulnerability cache")
                print(f"   Old hash: {cached_hash}")
                print(f"   New hash: {current_hash}")
                
                # Remove all cached vulnerability queries (except metadata)
                if CACHE_DIR.exists():
                    for file in CACHE_DIR.glob("*.json"):
                        if file != CACHE_METADATA_FILE:
                            try:
                                file.unlink()
                                print(f"   Deleted: {file.name}")
                            except Exception as e:
                                print(f"   Warning: Could not delete {file.name}: {e}")
        except Exception as e:
            print(f"⚠️ Could not read cache metadata: {e}")
            print("   Proceeding with cache as-is (may contain stale data)")
    
    # Update metadata with current hash
    try:
        CACHE_DIR.mkdir(exist_ok=True, parents=True)
        with open(CACHE_METADATA_FILE, "w") as f:
            json.dump({
                "dependency_manifest_hash": current_hash,
                "timestamp": os.path.getmtime(
                    "package.json" if os.path.exists("package.json") else
                    "requirements.txt" if os.path.exists("requirements.txt") else
                    "pom.xml" if os.path.exists("pom.xml") else
                    "go.mod"
                )
            }, f, indent=2)
    except Exception as e:
        print(f"⚠️ Could not update cache metadata: {e}")


def query_osv(package_name, version, ecosystem=None):
    """Query OSV API for vulnerabilities"""
    # Validate and invalidate cache if needed before querying
    _invalidate_cache_if_needed()
    
    cfg = get_config()
    osv_api_url = cfg.get_api_endpoint('osv')

    payload = {
        "package": {
            "name": package_name
        },
        "version": version
    }

    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem

    try:
        response = requests.post(osv_api_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[ERROR] OSV query failed for {package_name}: {e}")
        return []

    vulnerabilities = []

    # Get CVSS numeric values from config
    cvss_values = cfg.get_cvss_numeric_values()

    for vuln in data.get("vulns", []):
        cvss_score = None

        # Try to extract CVSS from severity field (score may be a vector string)
        if "severity" in vuln:
            for sev in vuln["severity"]:
                parsed = _parse_cvss_score(sev.get("score"))
                if parsed is not None:
                    cvss_score = parsed
                    break

        # Try to extract from database_specific field (common in OSV)
        if cvss_score is None and "database_specific" in vuln:
            try:
                db_spec = vuln["database_specific"]
                if "severity" in db_spec:
                    # Use severity mappings from config
                    severity_text = db_spec["severity"].upper()
                    cvss_score = cvss_values.get(severity_text, None)
            except:
                pass

        # Mark as UNKNOWN if no score available instead of assuming HIGH
        # This prevents false positives
        if cvss_score is None:
            cvss_score = cvss_values.get('UNKNOWN', 0.0)

        vulnerabilities.append({
            "id": vuln.get("id"),
            "source": "OSV",
            "summary": vuln.get("summary"),
            "cvss": cvss_score,
            "has_cvss": cvss_score > 0.0,  # Flag for manual review if needed
            "raw_data": vuln  # Include full OSV data for remediation extraction
        })

    return vulnerabilities