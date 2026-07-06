import os
import sys
import json
import time
import hashlib
from datetime import datetime

def tune_system(feedback_type, target, action_type, incident_id, reason, whitelist_path="whitelist.json", log_path="tuning_history.log"):
    print(f"[*] Starting Guardrails & Playbook Tuning for Incident: {incident_id}...")
    
    # Resolve whitelist path
    if not os.path.isabs(whitelist_path):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        whitelist_path = os.path.join(dir_path, whitelist_path)

    # 1. Read existing whitelist
    whitelist = {"ips": [], "hosts": [], "domains": []}
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, "r", encoding="utf-8") as f:
                whitelist = json.load(f)
        except Exception as e:
            print(f"[-] Error reading whitelist: {e}")
            return False
            
    updated = False
    details = ""
    
    # 2. Apply tuning logic based on feedback
    if feedback_type.upper() == "FP": # False Positive
        # Add target to whitelist so it will not be blocked in the future
        target_lower = target.strip().lower()
        
        if action_type == "block_ip":
            # Add to ips if not present
            if target not in whitelist.setdefault("ips", []):
                whitelist["ips"].append(target)
                updated = True
                details = f"Added IP {target} to whitelist to prevent false positive."
        elif action_type == "quarantine_host":
            # Add to hosts if not present
            if target not in whitelist.setdefault("hosts", []):
                whitelist["hosts"].append(target)
                updated = True
                details = f"Added Host {target} to whitelist to prevent false positive."
        elif action_type == "block_domain":
            # Add to domains if not present
            if target_lower not in [d.lower() for d in whitelist.setdefault("domains", [])]:
                whitelist["domains"].append(target)
                updated = True
                details = f"Added Domain {target} to whitelist to prevent false positive."
                
    elif feedback_type.upper() == "FN": # False Negative
        # Target was allowed when it should have been blocked.
        # Remove target from whitelist if it exists there by mistake.
        target_lower = target.strip().lower()
        
        # Scan and remove from all whitelist lists
        for cat in ["ips", "hosts", "domains"]:
            if cat in whitelist:
                # Find matching target case-insensitive
                to_remove = [item for item in whitelist[cat] if item.strip().lower() == target_lower]
                if to_remove:
                    for item in to_remove:
                        whitelist[cat].remove(item)
                    updated = True
                    details = f"Removed {target} from whitelist categories: {cat} to correct false negative."
                    
    # 3. Save updated whitelist if changed
    if updated:
        try:
            with open(whitelist_path, "w", encoding="utf-8") as f:
                json.dump(whitelist, f, indent=2)
            print(f"[+] Whitelist successfully updated: {details}")
        except Exception as e:
            print(f"[-] Failed to save updated whitelist: {e}")
            return False
    else:
        print("[*] No changes needed in whitelist for this feedback.")
        details = "No changes to whitelist needed (target state already correct)."

    # 4. Log tuning activity to history file
    now = datetime.utcnow().isoformat() + "Z"
    log_entry = {
        "timestamp": now,
        "incident_id": incident_id,
        "feedback_type": feedback_type,
        "target": target,
        "action_type": action_type,
        "reason": reason,
        "result_details": details
    }
    
    # Calculate checksum for the log entry to prevent log tampering
    entry_str = json.dumps(log_entry, sort_keys=True)
    entry_hash = hashlib.sha256(entry_str.encode("utf-8")).hexdigest()
    log_entry["checksum"] = entry_hash
    
    try:
        with open(log_path, "a", encoding="utf-8") as lf:
            lf.write(json.dumps(log_entry) + "\n")
        print(f"[+] Tuning event successfully logged to {log_path}")
        return True
    except Exception as e:
        print(f"[-] Failed to write to tuning history log: {e}")
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Aegis SOAR Guardrails & Playbooks Tuning Tool")
    parser.add_argument("--incident", required=True, help="Incident ID that triggered the review")
    parser.add_argument("--type", required=True, choices=["FP", "FN"], help="Feedback type: FP (False Positive) or FN (False Negative)")
    parser.add_argument("--target", required=True, help="Target resource IP/Host/Domain to tune")
    parser.add_argument("--action", required=True, help="Action type associated with the incident (e.g., block_ip, quarantine_host)")
    parser.add_argument("--reason", required=True, help="Reason/Rationale for this tuning adjustment")
    parser.add_argument("--whitelist", default="whitelist.json", help="Path to whitelist.json file")
    parser.add_argument("--history", default="tuning_history.log", help="Path to tuning_history.log file")
    
    args = parser.parse_args()
    success = tune_system(
        feedback_type=args.type,
        target=args.target,
        action_type=args.action,
        incident_id=args.incident,
        reason=args.reason,
        whitelist_path=args.whitelist,
        log_path=args.history
    )
    sys.exit(0 if success else 1)
