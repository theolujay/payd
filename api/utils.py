import hmac
import secrets
import hashlib
import logging
from typing import Optional, List
from datetime import datetime, timedelta

import jwt
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from ninja.security import HttpBearer, APIKeyHeader
from ninja.errors import HttpError

from api.models import APIKey, User

logger = logging.getLogger(__name__)


API_KEY_HEADER_SPEC = {
    "parameters": [
        {
            "name": "X-API-Key",
            "in": "header",
            "required": False,
            "schema": {
                "type": "string",
                "pattern": "^payd_live_[a-zA-Z0-9_-]{43,}$"
            },
            "description": "API key"
        },
        # {
        #     "name": "Authorization",
        #     "in": "header",
        #     "required": False,
        #     "schema": {
        #         "type": "string",
        #         "pattern": "^(Bearer )?[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]*$"
        #     },
        #     "description": "Access token"
        # }
    ],
    "security": [
        {"ApiKeyAuth": []},
        # {"BearerAuth": []}
    ]
}

def generate_api_key():
    """
    Generate a secure API key with a prefix for easy identification.
    
    Returns:
        tuple: (plain_key, hashed_key)
        - plain_key: The key to show the user (only shown once)
        - hashed_key: The hashed version to store in database
    
    Format: payd_live_<32-char-random-string>
    Example: payd_live_a7f3k9m2p1x5c8v4b6n0q3r7w9y2z5
    """
    
    random_part = secrets.token_urlsafe(32)
    plain_key = f"payd_live_{random_part}"
    hashed_key = make_password(plain_key)
    lookup_hint = _generate_lookup_hint(plain_key)
    
    return plain_key, hashed_key, lookup_hint


def verify_api_key(plain_key: str) -> Optional[APIKey]:
    """
    Verify an API key against stored hashes.
    
    Args:
        plain_key: The plain text API key from the request
        
    Returns:
        APIKey object if valid, None if invalid
        
    How it works:
    1. Check if key has correct format (starts with 'payd_live_')
    2. Query all active API keys for this user's account
    3. Use constant-time comparison to prevent timing attacks
    4. Return the matching APIKey object or None
    """

    if not plain_key or not plain_key.startswith("payd_live_"):
        logger.info("No plain_key or doesn't start with 'payd_live'")
        return None
    
    key_prefix = _generate_lookup_hint(plain_key)
    
    try:
        potential_keys = APIKey.objects.filter(
            lookup_hint=key_prefix,
            is_active=True
        )
        
        for api_key in potential_keys:
            if check_password(plain_key, api_key.key_hash):
                return api_key
        logger.info("couldn't find a match")
        return None
        
    except APIKey.DoesNotExist:
        logger.info("looks like the api key doesn't exist")
        return None


def _generate_lookup_hint(plain_key: str) -> str:
    """
    Generate a safe lookup hint from the plain key.
    
    This creates a short hash of the key that's safe to store
    alongside the full hash. It allows fast database lookups
    without exposing any part of the actual key.
    
    Args:
        plain_key: The plain text API key
        
    Returns:
        A 10-character hash prefix for database indexing
    """
    hash_obj = hashlib.sha256(plain_key.encode('utf-8'))
    return hash_obj.hexdigest()[:10]

class APIKeyAuth(APIKeyHeader):
    """API Key authentication using X-API-Key header"""
    
    param_name = "X-API-Key"  # this tells Swagger to use this header
    
    def __init__(self, permissions: List[str] = None):
        self.permissions = permissions or []
        super().__init__()
    
    def authenticate(self, request, key: Optional[str]) -> Optional[User]:
        if not key:
            return None
        
        try:
            api_key = verify_api_key(key)
            
            if not api_key:
                raise HttpError(401, "API key invalid")
            
            if not api_key.is_active:
                raise HttpError(401, "API key has been revoked")
            
            if (
                hasattr(api_key, "expires_at")
                and api_key.expires_at
                and api_key.expires_at < timezone.now()
            ):
                raise HttpError(401, "API key has expired")

            if self.permissions:
                missing_perms = set(self.permissions) - set(api_key.permissions)
                if missing_perms:
                    perm_name = missing_perms.pop()
                    raise HttpError(
                        403, f"API key lacks required permission: {perm_name}"
                    )
            
            return api_key.user
            
        except APIKey.DoesNotExist:
            raise HttpError(401, "Invalid API key")


class JWTAuth(HttpBearer):
    """JWT token authentication using Authorization: Bearer header"""
    
    def __init__(self, permissions: List[str] = None):
        self.permissions = permissions or []
        super().__init__()
    
    def authenticate(self, request, token: str) -> Optional[User]:
        if not token:
            return None
        
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
            user_id = payload.get("user_id")
            if not user_id:
                return None
            
            user = User.objects.get(id=user_id)
            
            return user
            
        except jwt.ExpiredSignatureError:
            raise HttpError(401, "JWT token has expired")
        except jwt.InvalidTokenError:
            raise HttpError(401, "Invalid JWT token")
        except User.DoesNotExist:
            return None

def dual_auth(permissions: List[str] = None):
    """
    Returns a list of auth schemes that accept EITHER JWT or API Key.
    Swagger will show both options in the UI.
    """
    return [JWTAuth(permissions=permissions), APIKeyAuth(permissions=permissions)]


def create_access_token(user: User) -> str:
    """Create access token (1 hour expiry)"""
    payload = {
        "user_id": str(user.id),
        "email": user.email,
        "exp": timezone.now() + timedelta(hours=1),
        "iat": timezone.now(),
        "type": "access",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_refresh_token(user: User) -> str:
    """Create refresh token (7 days expiry)"""
    payload = {
        "user_id": str(user.id),
        "exp": timezone.now() + timedelta(days=7),
        "iat": timezone.now(),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_tokens_for_user(user: User) -> dict:
    """Create both access and refresh tokens"""
    return {"access": create_access_token(user), "refresh": create_refresh_token(user)}


def refresh_access_token(refresh_token: str) -> Optional[str]:
    """Generate new access token from refresh token"""
    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"])

        if payload.get("type") != "refresh":
            return None

        user_id = payload.get("user_id")
        user = User.objects.get(id=user_id)

        return create_access_token(user)

    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
        return None


def verify_paystack_signature(payload: bytes, signature: str) -> bool:
    """
    Verify Paystack webhook signature using HMAC SHA512.

    Args:
        payload: Raw request body as bytes
        signature: Signature from x-paystack-signature header

    Returns:
        bool: True if signature is valid, False otherwise
    """
    computed_signature = hmac.new(
        settings.PAYSTACK_SECRET_KEY.encode("utf-8"), payload, hashlib.sha512
    ).hexdigest()

    return hmac.compare_digest(computed_signature, signature)


class GoogleOAuthConfig:
    CLIENT_ID = settings.GOOGLE_OAUTH_CLIENT_ID
    CLIENT_SECRET = settings.GOOGLE_OAUTH_CLIENT_SECRET
    REDIRECT_URI = settings.GOOGLE_OAUTH_REDIRECT_URI
    SCOPES = ["openid", "email", "profile"]
    AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URI = "https://oauth2.googleapis.com/token"
    USERINFO_URI = "https://www.googleapis.com/oauth2/v1/userinfo"
