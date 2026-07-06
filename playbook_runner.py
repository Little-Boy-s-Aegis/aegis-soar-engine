import json
import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("soar-engine.playbook-runner")

class PlaybookRunner:
    def __init__(self, playbooks_path="playbooks.json"):
        # Make path relative to this script directory if not absolute
        if not os.path.isabs(playbooks_path):
            dir_path = os.path.dirname(os.path.realpath(__file__))
            playbooks_path = os.path.join(dir_path, playbooks_path)
            
        self.playbooks_path = playbooks_path
        self.playbooks = {}
        self.load_playbooks()

    def load_playbooks(self):
        try:
            if os.path.exists(self.playbooks_path):
                with open(self.playbooks_path, "r", encoding="utf-8") as f:
                    self.playbooks = json.load(f)
                logger.info(f"Loaded {len(self.playbooks)} playbooks from {self.playbooks_path}")
            else:
                logger.warning(f"Playbooks path {self.playbooks_path} not found.")
        except Exception as e:
            logger.error(f"Failed to load playbooks from JSON: {e}")

    def execute_playbook(self, playbook_id: str, context: dict) -> list:
        """
        Executes a playbook based on the DSL definition, evaluating if/else,
        looping over target entities, and running steps in parallel.
        Returns a list of resolved action dictionaries.
        """
        playbook = self.playbooks.get(playbook_id)
        if not playbook:
            logger.warning(f"Playbook {playbook_id} not found in library.")
            return []

        logger.info(f"Starting execution of playbook {playbook_id}: '{playbook.get('name')}'")
        resolved_actions = []
        
        steps = playbook.get("steps", [])
        self._process_steps(steps, context, resolved_actions)
        
        logger.info(f"Completed execution of playbook {playbook_id}. Resolved {len(resolved_actions)} actions.")
        return resolved_actions

    def _process_steps(self, steps: list, context: dict, resolved_actions: list):
        for step in steps:
            step_type = step.get("type")
            if step_type == "action":
                self._execute_action_step(step, context, resolved_actions)
            elif step_type == "if_else":
                self._execute_if_else_step(step, context, resolved_actions)
            elif step_type == "parallel":
                self._execute_parallel_step(step, context, resolved_actions)
            else:
                logger.warning(f"Unknown step type: {step_type}")

    def _execute_action_step(self, step: dict, context: dict, resolved_actions: list):
        action_type = step.get("action_type")
        target_expr = step.get("target")
        loop = step.get("loop", False)
        approval_mode = step.get("approval_mode", "APPROVAL_REQUIRED")
        rationale = step.get("rationale", "")

        # Error handling properties
        retry = step.get("retry")
        fallback_step = step.get("fallback_step")

        # Determine phase based on action type
        phase = "contain"
        if action_type in ("preserve_logs", "preserve_evidence"):
            phase = "preserve"
        elif action_type in ("notify_soc", "open_ticket"):
            phase = "notify"
        elif action_type in ("hunt_telemetry", "hunt_malware"):
            phase = "hunt"

        # Resolve targets from context
        targets = []
        if target_expr.startswith("entities."):
            entity_key = target_expr.split(".")[1]
            targets = context.get("verified_case", {}).get("entities", {}).get(entity_key, [])
            # Fallback to direct context if verified_case not structured this way
            if not targets:
                targets = context.get("entities", {}).get(entity_key, [])
            # Fallback if it's not a list
            if not isinstance(targets, list):
                targets = [targets] if targets else []
        else:
            targets = [target_expr]

        if not targets:
            logger.info(f"No targets found for step {step.get('step_id')} (expr: {target_expr})")
            return

        if loop:
            for t in targets:
                resolved_actions.append(self._create_action_obj(action_type, t, phase, approval_mode, rationale, retry, fallback_step))
        else:
            # Single action using joint targets
            resolved_actions.append(self._create_action_obj(action_type, ", ".join(targets), phase, approval_mode, rationale, retry, fallback_step))

    def _is_safe_condition(self, condition: str) -> bool:
        if not condition:
            return False
        # Block dangerous keywords, private properties, or introspection to prevent Sandbox escape
        dangerous = ["__", "import", "eval", "exec", "getattr", "setattr", "globals", "locals", "sys", "os", "subprocess", "class", "base", "subclasses", "mro"]
        lower_cond = condition.lower()
        for word in dangerous:
            if word in lower_cond:
                return False
        return True

    def _execute_if_else_step(self, step: dict, context: dict, resolved_actions: list):
        condition = step.get("condition")
        then_steps = step.get("then_steps", [])
        else_steps = step.get("else_steps", [])

        # Create evaluation environment with safe context variables
        eval_env = {
            "risk_score": context.get("scoring", {}).get("final_risk_score_0_10", 0.0),
            "threat_confirmed": context.get("verified_case", {}).get("threat_confirmed", False)
        }

        result = False
        # Sanitize condition to prevent arbitrary code execution / sandbox escape
        if not self._is_safe_condition(condition):
            logger.error(f"[SECURITY ALERT] Unsafe condition string detected: {condition}. Skipping evaluation.")
        else:
            try:
                # Safely evaluate condition using python eval
                result = eval(condition, {"__builtins__": None}, eval_env)
                logger.info(f"Evaluated condition '{condition}' -> {result}")
            except Exception as e:
                logger.error(f"Failed to evaluate condition '{condition}': {e}")
                result = False

        if result:
            self._process_steps(then_steps, context, resolved_actions)
        else:
            self._process_steps(else_steps, context, resolved_actions)

    def _execute_parallel_step(self, step: dict, context: dict, resolved_actions: list):
        parallel_steps = step.get("parallel_steps", [])
        logger.info(f"Executing {len(parallel_steps)} steps in parallel...")

        import threading
        lock = threading.Lock()
        
        def run_step(p_step):
            local_resolved = []
            step_type = p_step.get("type")
            if step_type == "action":
                self._execute_action_step(p_step, context, local_resolved)
            elif step_type == "if_else":
                self._execute_if_else_step(p_step, context, local_resolved)
            elif step_type == "parallel":
                self._execute_parallel_step(p_step, context, local_resolved)
            
            with lock:
                resolved_actions.extend(local_resolved)

        with ThreadPoolExecutor(max_workers=max(1, len(parallel_steps))) as executor:
            executor.map(run_step, parallel_steps)

    def _create_action_obj(self, action_type: str, target: str, phase: str, approval_mode: str, rationale: str, retry: dict = None, fallback_step: dict = None) -> dict:
        action_obj = {
            "action_id": f"act-{uuid.uuid4().hex[:8]}",
            "action_type": action_type,
            "phase": phase,
            "status": "pending",
            "rationale": rationale,
            "target": {
                "type": "IP" if action_type == "block_ip" else "HOST" if action_type == "quarantine_host" else "USER" if action_type == "force_logout" else "ACCOUNT",
                "value_masked": target
            },
            "approval_mode": approval_mode
        }
        if retry:
            action_obj["retry"] = retry
        if fallback_step:
            action_obj["fallback_step"] = fallback_step
        return action_obj
