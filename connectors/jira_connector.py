import logging
import requests
import os
from requests.auth import HTTPBasicAuth
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.jira")


class JiraConnector:
    """API Connector for JIRA REST API to create and manage security incident tickets."""

    def __init__(self):
        self.jira_url = os.getenv("JIRA_URL", "https://your-domain.atlassian.net")
        self.jira_user = os.getenv("JIRA_USER", "soc-bot@company.com")
        self.api_token = secrets.get_secret("JIRA_API_TOKEN", "mock-jira-token")
        self.project_key = os.getenv("JIRA_PROJECT_KEY", "SOC")
        self.verify_ssl = os.getenv("JIRA_VERIFY_SSL", "true").lower() == "true"

    def _is_simulation(self) -> bool:
        """Returns True if running in simulation/mock mode."""
        return self.api_token == "mock-jira-token"

    def _get_auth(self) -> HTTPBasicAuth:
        """Returns HTTP Basic Auth credentials for JIRA API."""
        return HTTPBasicAuth(self.jira_user, self.api_token)

    def _get_headers(self) -> dict:
        """Returns standard headers for JIRA API requests."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def create_ticket(
        self, title: str, description: str, priority: str, labels: list = None
    ) -> tuple[bool, str]:
        """
        Creates a new JIRA issue in the configured project.
        Priority should be one of: Highest, High, Medium, Low, Lowest.
        Returns (success, message).
        """
        logger.info(f"[JIRA] Creating ticket: {title} (priority={priority}, project={self.project_key})")

        if labels is None:
            labels = ["soar-engine", "security-incident"]

        if self._is_simulation():
            mock_key = f"{self.project_key}-{1001}"
            logger.info(
                f"[JIRA-SIMULATION] Created ticket {mock_key}: {title} "
                f"(priority={priority}, labels={labels})."
            )
            return True, f"[SIMULATION] JIRA ticket {mock_key} created: {title}"

        url = f"{self.jira_url}/rest/api/2/issue"
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": title,
                "description": description,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority},
                "labels": labels,
            }
        }

        try:
            res = requests.post(
                url,
                json=payload,
                auth=self._get_auth(),
                headers=self._get_headers(),
                verify=self.verify_ssl,
                timeout=15,
            )
            if res.status_code in (200, 201):
                result = res.json()
                issue_key = result.get("key", "unknown")
                logger.info(f"[JIRA] Ticket created successfully: {issue_key}")
                return True, f"JIRA ticket {issue_key} created: {title}"
            else:
                logger.error(f"[JIRA] HTTP {res.status_code}: {res.text}")
                return False, f"Failed to create JIRA ticket: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[JIRA ERROR] Failed to create ticket: {e}")
            return False, f"JIRA connection error: {str(e)}"

    def update_ticket(self, issue_key: str, status: str, comment: str = None) -> tuple[bool, str]:
        """
        Transitions a JIRA issue to a new status and optionally adds a comment.
        Returns (success, message).
        """
        logger.info(f"[JIRA] Updating ticket {issue_key}: status={status}")

        if self._is_simulation():
            logger.info(
                f"[JIRA-SIMULATION] Ticket {issue_key} transitioned to '{status}'."
            )
            if comment:
                logger.info(f"[JIRA-SIMULATION] Comment added to {issue_key}: {comment[:80]}...")
            return True, f"[SIMULATION] JIRA ticket {issue_key} updated to '{status}'."

        # Step 1: Get available transitions to find the target status ID
        try:
            transitions_url = f"{self.jira_url}/rest/api/2/issue/{issue_key}/transitions"
            res = requests.get(
                transitions_url,
                auth=self._get_auth(),
                headers=self._get_headers(),
                verify=self.verify_ssl,
                timeout=10,
            )
            if res.status_code != 200:
                return False, f"Failed to get transitions for {issue_key}: HTTP {res.status_code}"

            transitions = res.json().get("transitions", [])
            target_transition = None
            for t in transitions:
                if t["name"].lower() == status.lower():
                    target_transition = t
                    break

            if not target_transition:
                available = [t["name"] for t in transitions]
                return False, (
                    f"Status '{status}' not available for {issue_key}. "
                    f"Available transitions: {available}"
                )

            # Step 2: Execute the transition
            transition_payload = {"transition": {"id": target_transition["id"]}}
            res = requests.post(
                transitions_url,
                json=transition_payload,
                auth=self._get_auth(),
                headers=self._get_headers(),
                verify=self.verify_ssl,
                timeout=10,
            )
            if res.status_code not in (200, 204):
                return False, f"Failed to transition {issue_key}: HTTP {res.status_code} - {res.text}"

            logger.info(f"[JIRA] Ticket {issue_key} transitioned to '{status}'.")

        except Exception as e:
            logger.error(f"[JIRA ERROR] Failed to transition ticket: {e}")
            return False, f"JIRA transition error: {str(e)}"

        # Step 3: Add comment if provided
        if comment:
            success, msg = self.add_comment(issue_key, comment)
            if not success:
                return True, f"Ticket {issue_key} transitioned to '{status}', but comment failed: {msg}"

        return True, f"JIRA ticket {issue_key} updated to '{status}'."

    def add_comment(self, issue_key: str, comment: str) -> tuple[bool, str]:
        """
        Adds a comment to an existing JIRA issue.
        Returns (success, message).
        """
        logger.info(f"[JIRA] Adding comment to {issue_key}")

        if self._is_simulation():
            logger.info(f"[JIRA-SIMULATION] Comment added to {issue_key}: {comment[:80]}...")
            return True, f"[SIMULATION] Comment added to JIRA ticket {issue_key}."

        url = f"{self.jira_url}/rest/api/2/issue/{issue_key}/comment"
        payload = {"body": comment}

        try:
            res = requests.post(
                url,
                json=payload,
                auth=self._get_auth(),
                headers=self._get_headers(),
                verify=self.verify_ssl,
                timeout=10,
            )
            if res.status_code in (200, 201):
                logger.info(f"[JIRA] Comment added to {issue_key} successfully.")
                return True, f"Comment added to JIRA ticket {issue_key}."
            else:
                logger.error(f"[JIRA] HTTP {res.status_code}: {res.text}")
                return False, f"Failed to add comment to {issue_key}: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[JIRA ERROR] Failed to add comment: {e}")
            return False, f"JIRA connection error: {str(e)}"
