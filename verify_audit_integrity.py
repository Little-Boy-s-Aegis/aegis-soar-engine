import json
import hashlib
import os
import sys

def verify_file_integrity(log_path="soar_audit.log"):
    if not os.path.exists(log_path):
        print(f"[-] Log file not found: {log_path}")
        return False

    print(f"[*] Verifying cryptographic integrity of log file: {log_path}...")
    expected_prev_hash = "0" * 64
    tampered = False
    count = 0

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if "AUDIT: " not in line:
                continue

            try:
                json_str = line.split("AUDIT: ")[1].strip()
                payload = json.loads(json_str)
                
                actual_hash = payload.get("hash")
                prev_hash = payload.get("prevHash")
                
                # 1. Verify prevHash link
                if prev_hash != expected_prev_hash:
                    print(f"[!] INTEGRITY FAILURE: Line {line_num} has broken link. Expected prevHash: {expected_prev_hash}, got: {prev_hash}")
                    tampered = True
                    break
                
                # 2. Re-calculate current hash canonically
                hash_payload = {
                    "timestamp": payload.get("timestamp"),
                    "eventType": payload.get("eventType"),
                    "incidentId": payload.get("incidentId"),
                    "details": payload.get("details"),
                    "prevHash": prev_hash
                }
                
                canonical_str = json.dumps(hash_payload, sort_keys=True)
                recalculated_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
                
                if recalculated_hash != actual_hash:
                    print(f"[!] INTEGRITY FAILURE: Line {line_num} hash mismatch. Recalculated: {recalculated_hash}, stored: {actual_hash}")
                    tampered = True
                    break
                
                expected_prev_hash = actual_hash
                count += 1
            except Exception as e:
                print(f"[!] Parse error on line {line_num}: {e}")
                tampered = True
                break

    if tampered:
        print("[-] Verification failed: Log file has been tampered with or corrupted!")
        return False
    else:
        print(f"[+] Verification success: Log chain is unbroken ({count} events verified).")
        return True

def verify_db_integrity():
    print("[*] Verifying cryptographic integrity of PostgreSQL audit logs...")
    try:
        import psycopg2
        from config import DATABASE_URL
        
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, timestamp, event_type, incident_id, details, hash, prev_hash FROM soar_audit_logs ORDER BY id ASC")
        rows = cursor.fetchall()
        conn.close()
        
        if not rows:
            print("[+] Verification success: Database table is empty.")
            return True
            
        expected_prev_hash = "0" * 64
        tampered = False
        count = 0
        
        for row in rows:
            row_id, timestamp, event_type, incident_id, details, stored_hash, prev_hash = row
            
            # Format timestamp to ISO format string match
            timestamp_str = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Strip hashes
            stored_hash = stored_hash.strip()
            prev_hash = prev_hash.strip()
            
            # 1. Verify prevHash link
            if prev_hash != expected_prev_hash:
                print(f"[!] INTEGRITY FAILURE: DB Record ID {row_id} has broken link. Expected prevHash: {expected_prev_hash}, got: {prev_hash}")
                tampered = True
                break
                
            # 2. Re-calculate current hash canonically
            hash_payload = {
                "timestamp": timestamp_str,
                "eventType": event_type,
                "incidentId": incident_id,
                "details": details,
                "prevHash": prev_hash
            }
            
            canonical_str = json.dumps(hash_payload, sort_keys=True)
            recalculated_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
            
            if recalculated_hash != stored_hash:
                print(f"[!] INTEGRITY FAILURE: DB Record ID {row_id} hash mismatch. Recalculated: {recalculated_hash}, stored: {stored_hash}")
                tampered = True
                break
                
            expected_prev_hash = stored_hash
            count += 1
            
        if tampered:
            print("[-] Verification failed: Database has been tampered with or corrupted!")
            return False
        else:
            print(f"[+] Verification success: Database log chain is unbroken ({count} records verified).")
            return True
            
    except Exception as e:
        print(f"[-] Failed to verify database logs: {e}")
        return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Aegis SOAR Log Chain Integrity Verification Utility")
    parser.add_argument("--file", help="Path to audit log file (default: soar_audit.log)", default="soar_audit.log")
    parser.add_argument("--db", action="store_true", help="Verify PostgreSQL centralized database logs")
    
    args = parser.parse_args()
    
    success = True
    if args.db:
        success = verify_db_integrity()
    else:
        success = verify_file_integrity(args.file)
        
    sys.exit(0 if success else 1)
