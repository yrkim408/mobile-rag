"""OAuth 2.0 manager with PKCE support for mobile/web clients"""
import os
import secrets
import hashlib
import base64
import time
from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import httpx
from google.cloud import secretmanager
import json

@dataclass
class OAuthConfig:
    """OAuth configuration with security best practices"""
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list
    auth_uri: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_uri: str = "https://oauth2.googleapis.com/token"
    use_pkce: bool = True
    state_timeout_seconds: int = 600  # 10 minutes

class PKCEChallenge:
    """Generate and verify PKCE challenges for OAuth security"""
    
    @staticmethod
    def generate_verifier(length: int = 128) -> str:
        """Generate cryptographically secure random verifier"""
        verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(length)
        ).decode('utf-8').rstrip('=')
        return verifier[:128]  # Ensure max length
    
    @staticmethod
    def generate_challenge(verifier: str) -> str:
        """Generate SHA256 challenge from verifier"""
        challenge = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(challenge).decode('utf-8').rstrip('=')

class SecretManagerClient:
    """Wrapper for Google Secret Manager"""
    
    def __init__(self, project_id: str):
        self.client = secretmanager.SecretManagerServiceClient()
        self.project_id = project_id
    
    def get_secret(self, secret_id: str, version: str = "latest") -> str:
        """Retrieve secret value from Secret Manager"""
        name = f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
        try:
            response = self.client.access_secret_version(name=name)
            return response.payload.data.decode('UTF-8')
        except Exception as e:
            print(f"Error accessing secret {secret_id}: {e}")
            # Fallback to environment variable for local development
            return os.environ.get(secret_id.upper().replace('-', '_'), '')

class OAuthManager:
    """Complete OAuth 2.0 manager with PKCE and Secret Manager integration"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.secret_client = SecretManagerClient(project_id)
        self.state_storage = {}  # In production, use Redis or Firestore
        self.config = self._load_config()
    
    def _load_config(self) -> OAuthConfig:
        """Load OAuth config from Secret Manager"""
        return OAuthConfig(
            client_id=self.secret_client.get_secret("oauth-client-id"),
            client_secret=self.secret_client.get_secret("oauth-client-secret"),
            redirect_uri=os.environ.get("OAUTH_REDIRECT_URI", "http://localhost:8080/auth/callback"),
            scopes=["openid", "email", "profile"]
        )
    
    def create_authorization_url(self, user_id: str) -> Tuple[str, str]:
        """Create authorization URL with PKCE challenge"""
        # Generate state token for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Generate PKCE challenge
        verifier = PKCEChallenge.generate_verifier()
        challenge = PKCEChallenge.generate_challenge(verifier)
        
        # Store state and verifier (with timeout)
        self.state_storage[state] = {
            'user_id': user_id,
            'verifier': verifier,
            'created_at': time.time(),
            'expires_at': time.time() + self.config.state_timeout_seconds
        }
        
        # Build authorization URL
        from urllib.parse import urlencode
        params = {
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(self.config.scopes),
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent',
            'code_challenge': challenge,
            'code_challenge_method': 'S256'
        }
        
        auth_url = f"{self.config.auth_uri}?{urlencode(params)}"
        return auth_url, state
    
    async def exchange_code(self, code: str, state: str) -> Dict:
        """Exchange authorization code for tokens"""
        # Validate state
        if state not in self.state_storage:
            raise ValueError("Invalid state parameter")
        
        state_data = self.state_storage[state]
        if time.time() > state_data['expires_at']:
            del self.state_storage[state]
            raise ValueError("State parameter expired")
        
        # Exchange code for tokens
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config.token_uri,
                data={
                    'code': code,
                    'client_id': self.config.client_id,
                    'client_secret': self.config.client_secret,
                    'redirect_uri': self.config.redirect_uri,
                    'grant_type': 'authorization_code',
                    'code_verifier': state_data['verifier']
                }
            )
        
        # Clean up state
        del self.state_storage[state]
        
        if response.status_code != 200:
            raise ValueError(f"Token exchange failed: {response.text}")
        
        return response.json()
