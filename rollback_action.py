import argparse
import sys
import os
import json
import logging
import time

# Add current dir to path to import connectors
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from connectors.fortinet import FortinetConnector
from connectors.active_directory import ActiveDirectoryConnector
from connectors.crowdstrike import CrowdStrikeConnector
from connectors.waf import WafConnector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("soar-rollback-tool")

def rollback_single_action(action_type: str, target: str, incident_id: str = "manual-rollback"):
    logger.info(f"Initiating rollback for action: {action_type} on target: {target} (Incident: {incident_id})")
    
    success = False
    message = "Unknown action type"

    # Normalize action types
    action_lower = action_type.lower().replace(" ", "_")

    if action_lower == "block_ip":
        # Rollback IP block on both Fortinet and AWS WAF
        fortinet = FortinetConnector()
        fn_ok, fn_msg = fortinet.unblock_ip(target)
        
        waf = WafConnector()
        waf_ok, waf_msg = waf.unblock_ip(target)
        
        success = fn_ok or waf_ok
        message = f"Fortinet: {fn_msg} | WAF: {waf_msg}"

    elif action_lower == "block_domain":
        fortinet = FortinetConnector()
        success, message = fortinet.unblock_domain(target)

    elif action_lower in ("disable_account", "revoke_credentials"):
        ad = ActiveDirectoryConnector()
        success, message = ad.enable_account(target)

    elif action_lower in ("quarantine_host", "isolate_host"):
        cs = CrowdStrikeConnector()
        success, message = cs.lift_isolation(target)

    elif action_lower in ("deploy_waf_rule", "deploy_mitigation_rule"):
        waf = WafConnector()
        success, message = waf.remove_mitigation_rule("MitigationRule", target)
        
    else:
        logger.warning(f"No rollback mechanism defined for action type: {action_type}")
        return False, f"Unsupported rollback for action: {action_type}"

    if success:
        logger.info(f"[ROLLBACK SUCCESS] Action {action_type} on target {target} has been reverted. Details: {message}")
        
        # Log to Audit Logger if possible
        try:
            from audit_logger import SoarAuditLogger
            # Disable PostgreSQL during manual test runs if not needed
            os.environ["SOAR_AUDIT_DB_ENABLED"] = "false"
            SoarAuditLogger.log_api_response(
                incident_id=incident_id,
                target_system="rollback_engine",
                action_type=f"rollback_{action_lower}",
                request_params={"target": target},
                success=True,
                response_msg=f"Rollback successful: {message}"
            )
        except Exception as ae:
            logger.error(f"Failed to write audit log: {ae}")
            
    else:
        logger.error(f"[ROLLBACK FAILED] Failed to revert action {action_type} on target {target}. Details: {message}")

    return success, message

def rollback_by_incident(incident_id: str):
    logger.info(f"Querying SOAR State Database (Redis) for executed actions on Incident: {incident_id}")
    
    try:
        import redis
        from config import REDIS_URL
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        redis_key = f"aegis:playbook:status:{incident_id}"
        
        actions_status_json = r.hget(redis_key, "actions_status")
        if not actions_status_json:
            logger.warning(f"No execution history found in Redis for incident {incident_id}.")
            return False, f"No history found for incident {incident_id}"
            
        actions_status = json.loads(actions_status_json)
        logger.info(f"Found {len(actions_status)} recorded actions for incident {incident_id}: {actions_status}")
        
        rolled_back_count = 0
        for action_key, status in actions_status.items():
            if status in ("executed", "simulated", "executing"):
                parts = action_key.split(":", 1)
                if len(parts) == 2:
                    act_type, target = parts
                    ok, msg = rollback_single_action(act_type, target, incident_id)
                    if ok:
                        rolled_back_count += 1
                        actions_status[action_key] = "rolled_back"
                        
        r.hset(redis_key, "actions_status", json.dumps(actions_status))
        r.hset(redis_key, "status", "ROLLED_BACK")
        r.hset(redis_key, "updated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        
        logger.info(f"[ROLLBACK COMPLETE] Successfully reverted {rolled_back_count} containment actions for Incident {incident_id}.")
        return True, f"Reverted {rolled_back_count} actions."
        
    except Exception as e:
        logger.error(f"Error executing rollback by incident: {e}")
        return False, str(e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis SOAR Action Rollback Engine")
    parser.add_argument("--incident-id", help="Rollback all containment actions for a specific Incident ID")
    parser.add_argument("--action", help="Action type to rollback (block_ip, disable_account, quarantine_host, block_domain)")
    parser.add_argument("--target", help="Target value (IP, username, host, domain) to release")
    
    args = parser.parse_args()
    
    if args.incident_id:
        success, msg = rollback_by_incident(args.incident_id)
        sys.exit(0 if success else 1)
    elif args.action and args.target:
        success, msg = rollback_single_action(args.action, args.target)
        sys.exit(0 if success else 1)
    else:
        parser.print_help()
        sys.exit(1)
