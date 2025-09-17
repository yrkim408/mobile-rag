"""
OAuth 2.0 with PKCE Implementation for Mobile RAG
"""
import os
import secrets
import hashlib
import base64
from typing import Optional, Dict
from datetime import datetime, timedelta
import httpx
from fastapi import HTTPException, Request
from jose import jwt, JWTError

class PKCEManager:
    """Manages PKCE flow for OAuth 2.0"""
    
    def __init__(self):
        self.pending_challenges = {}  # In production, use Redis
        
    def generate_challenge(self) -> tuple[str, str]:
        """Generate PKCE verifier and challenge"""
        # Generate cryptographically secure verifier
        verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Generate SHA256 challenge
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        
        return verifier, challenge
    
    def store_challenge(self, state: str, verifier: str):
        """Store verifier for later verification"""
        self.pending_challenges[state] = {
            'verifier': verifier,
            'timestamp': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=10)
        }
    
    def verify_challenge(self, state: str, code_verifier: str) -> bool:
        """Verify the PKCE challenge"""
        if state not in self.pending_challenges:
            return False
            
        stored = self.pending_challenges[state]
        
        # Check expiration
        if datetime.utcnow() > stored['expires_at']:
            del self.pending_challenges[state]
            return False
        
        # Verify challenge
        is_valid = stored['verifier'] == code_verifier
        
        # Clean up
        del self.pending_challenges[state]
        
        return is_valid

class OAuthClient:
    """OAuth 2.0 client with PKCE support"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.pkce_manager = PKCEManager()
        self.token_endpoint = "https://oauth2.googleapis.com/token"
        self.auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
        
    def get_authorization_url(self, scopes: list[str]) -> Dict[str, str]:
        """Generate authorization URL with PKCE"""
        state = secrets.token_urlsafe(32)
        verifier, challenge = self.pkce_manager.generate_challenge()
        
        # Store verifier for later
        self.pkce_manager.store_challenge(state, verifier)
        
        # Build authorization URL
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(scopes),
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent',
            'code_challenge': challenge,
            'code_challenge_method': 'S256'
        }
        
        # Create URL
        from urllib.parse import urlencode
        auth_url = f"{self.auth_endpoint}?{urlencode(params)}"
        
        return {
            'auth_url': auth_url,
            'state': state,
            'verifier': verifier  # Client needs to store this
        }
    
    async def exchange_code(self, code: str, code_verifier: str) -> Dict:
        """Exchange authorization code for tokens"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.token_endpoint,
                data={
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'code': code,
                    'code_verifier': code_verifier,
                    'redirect_uri': self.redirect_uri,
                    'grant_type': 'authorization_code'
                }
            )
            
            if response.status_code != 200:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Token exchange failed: {response.text}"
                )
            
            return response.json()
