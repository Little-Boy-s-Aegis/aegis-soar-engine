import logging
import requests
import os
from secret_manager import secrets

logger = logging.getLogger("soar-engine.connectors.active_directory")

class ActiveDirectoryConnector:
    """API Connector for Active Directory and Entra ID (Azure AD) to manage compromised accounts."""

    def __init__(self):
        # Entra ID credentials
        self.tenant_id = os.getenv("ENTRA_TENANT_ID", "mock-tenant-id")
        self.client_id = os.getenv("ENTRA_CLIENT_ID", "mock-client-id")
        self.client_secret = secrets.get_secret("ENTRA_CLIENT_SECRET", "mock-client-secret")
        
        # On-premises AD LDAP settings
        self.ldap_server = os.getenv("AD_LDAP_SERVER", "ldap://domaincontroller.local:389")
        self.ldap_user = os.getenv("AD_LDAP_USER", "CN=Admin,CN=Users,DC=domain,DC=local")
        self.ldap_password = secrets.get_secret("AD_LDAP_PASSWORD", "mock-ldap-password")

    def _get_entra_token(self) -> str:
        """Fetches Microsoft Graph API access token using Client Credentials flow."""
        if self.client_secret == "mock-client-secret":
            return "mock-entra-token"
            
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        payload = {
            "client_id": self.client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": self.client_secret,
            "grant_type": "client_credentials"
        }
        res = requests.post(url, data=payload, timeout=10)
        if res.status_code == 200:
            return res.json().get("access_token")
        raise Exception(f"Failed to get Entra ID token: HTTP {res.status_code} - {res.text}")

    def disable_account(self, username: str) -> tuple:
        """
        Disables a user account in both Entra ID (Graph API) and on-premises AD (LDAP).
        Returns (success, message).
        """
        logger.info(f"[ACTIVE DIRECTORY] Request to disable account: {username}")
        
        # 1. Entra ID / Microsoft Graph API logic
        try:
            token = self._get_entra_token()
            if token == "mock-entra-token":
                logger.info(f"[ENTRA ID-SIMULATION] Disabled user account {username} via Microsoft Graph API.")
            else:
                # Disable via MS Graph API
                url = f"https://graph.microsoft.com/v1.0/users/{username}"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                payload = {"accountEnabled": False}
                res = requests.patch(url, headers=headers, json=payload, timeout=10)
                if res.status_code not in (200, 204):
                    return False, f"Failed to disable Entra ID account: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[ENTRA ID ERROR] Graph API call failed: {e}")
            # Continue to LDAP in case it's hybrid
            
        # 2. On-premises Active Directory via LDAP (ldap3 package is optional, we simulate or use it if available)
        try:
            if self.ldap_password == "mock-ldap-password":
                logger.info(f"[ON-PREM AD-SIMULATION] Disabled user account {username} in Active Directory (UserAccountControl: 514).")
                return True, f"[SIMULATION] Account {username} disabled in AD/Entra ID."
            else:
                import ldap3
                server = ldap3.Server(self.ldap_server, get_info=ldap3.ALL)
                conn = ldap3.Connection(server, self.ldap_user, self.ldap_password, auto_bind=True)
                
                # Search user DN
                search_filter = f"(sAMAccountName={username})"
                conn.search("DC=domain,DC=local", search_filter, attributes=["userAccountControl"])
                if conn.entries:
                    user_dn = conn.entries[0].entry_dn
                    # 514 is NORMAL_ACCOUNT (512) + ACCOUNTDISABLE (2)
                    conn.modify(user_dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [514])]})
                    return True, f"Account {username} disabled in AD (DN: {user_dn})."
                else:
                    return False, f"User {username} not found in Active Directory LDAP."
        except Exception as e:
            logger.error(f"[AD LDAP ERROR] LDAP call failed: {e}")
            return False, f"AD/Entra ID disable failed: {str(e)}"

    def reset_password(self, username: str, new_password: str = None) -> tuple:
        """
        Resets user password in both Entra ID (Graph API) and on-premises AD (LDAP).
        Returns (success, message).
        """
        logger.info(f"[ACTIVE DIRECTORY] Request to reset password for account: {username}")
        if not new_password:
            import string
            import random
            # Generate a secure random password if none is provided
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            new_password = "".join(random.choice(chars) for _ in range(16))
            
        # 1. Entra ID / Microsoft Graph API logic
        try:
            token = self._get_entra_token()
            if token == "mock-entra-token":
                logger.info(f"[ENTRA ID-SIMULATION] Reset password for user account {username} via Graph API.")
            else:
                url = f"https://graph.microsoft.com/v1.0/users/{username}"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "passwordProfile": {
                        "forceChangePasswordNextSignIn": True,
                        "password": new_password
                    }
                }
                res = requests.patch(url, headers=headers, json=payload, timeout=10)
                if res.status_code not in (200, 204):
                    return False, f"Failed to reset Entra ID password: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[ENTRA ID ERROR] Graph API reset password failed: {e}")
            
        # 2. On-premises Active Directory via LDAP
        try:
            if self.ldap_password == "mock-ldap-password":
                logger.info(f"[ON-PREM AD-SIMULATION] Reset password for user {username} and set changePwdOnNextLogon=True.")
                return True, f"[SIMULATION] Password reset successfully for account {username}."
            else:
                import ldap3
                server = ldap3.Server(self.ldap_server, get_info=ldap3.ALL)
                conn = ldap3.Connection(server, self.ldap_user, self.ldap_password, auto_bind=True)
                
                search_filter = f"(sAMAccountName={username})"
                conn.search("DC=domain,DC=local", search_filter)
                if conn.entries:
                    user_dn = conn.entries[0].entry_dn
                    unicode_pwd = f'"{new_password}"'.encode("utf-16-le")
                    conn.modify(user_dn, {"unicodePwd": [(ldap3.MODIFY_REPLACE, [unicode_pwd])]})
                    conn.modify(user_dn, {"pwdLastSet": [(ldap3.MODIFY_REPLACE, [0])]})
                    return True, f"Password reset for account {username} in AD (DN: {user_dn})."
                else:
                    return False, f"User {username} not found in Active Directory LDAP."
        except Exception as e:
            logger.error(f"[AD LDAP ERROR] LDAP password reset failed: {e}")
            return False, f"AD/Entra ID password reset failed: {str(e)}"

    def enable_account(self, username: str) -> tuple:
        """
        Enables a user account in both Entra ID (Graph API) and on-premises AD (LDAP).
        Returns (success, message).
        """
        logger.info(f"[ACTIVE DIRECTORY] Request to enable account: {username}")
        
        # 1. Entra ID / Microsoft Graph API logic
        try:
            token = self._get_entra_token()
            if token == "mock-entra-token":
                logger.info(f"[ENTRA ID-SIMULATION] Enabled user account {username} via Microsoft Graph API.")
            else:
                url = f"https://graph.microsoft.com/v1.0/users/{username}"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                }
                payload = {"accountEnabled": True}
                res = requests.patch(url, headers=headers, json=payload, timeout=10)
                if res.status_code not in (200, 204):
                    return False, f"Failed to enable Entra ID account: HTTP {res.status_code} - {res.text}"
        except Exception as e:
            logger.error(f"[ENTRA ID ERROR] Graph API call failed: {e}")
            
        # 2. On-premises Active Directory via LDAP
        try:
            if self.ldap_password == "mock-ldap-password":
                logger.info(f"[ON-PREM AD-SIMULATION] Enabled user account {username} in Active Directory (UserAccountControl: 512).")
                return True, f"[SIMULATION] Account {username} enabled in AD/Entra ID."
            else:
                import ldap3
                server = ldap3.Server(self.ldap_server, get_info=ldap3.ALL)
                conn = ldap3.Connection(server, self.ldap_user, self.ldap_password, auto_bind=True)
                
                search_filter = f"(sAMAccountName={username})"
                conn.search("DC=domain,DC=local", search_filter, attributes=["userAccountControl"])
                if conn.entries:
                    user_dn = conn.entries[0].entry_dn
                    # 512 is NORMAL_ACCOUNT
                    conn.modify(user_dn, {"userAccountControl": [(ldap3.MODIFY_REPLACE, [512])]})
                    return True, f"Account {username} enabled in AD (DN: {user_dn})."
                else:
                    return False, f"User {username} not found in Active Directory LDAP."
        except Exception as e:
            logger.error(f"[AD LDAP ERROR] LDAP call failed: {e}")
            return False, f"AD/Entra ID enable failed: {str(e)}"
