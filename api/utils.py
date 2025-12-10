import hmac
import secrets
import hashlib
from typing import Optional, List
from datetime import datetime, timedelta
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password

import jwt
from django.conf import settings
from ninja.security import HttpBearer

from api.models import APIKey, User

def generate_api_key():
    """
    Make a secure, hashed API key
    """
    plain_key = secrets.token_urlsafe(32)
    hashed_key = make_password(plain_key)
    return plain_key, hashed_key
    
def verify_api_key(plain_key):
    try:
        api_key = APIKey.objects.get(key_hash__startswith=plain_key[:10])
        if check_password(plain_key, api_key.key_hash):
            return api_key
    except APIKey.DoesNotExist:
        return None
    
from ninja.security import HttpBearer
from ninja.errors import HttpError

class JWTAPIKeyAuth(HttpBearer):
    """JWT Authentication with dual auth support"""
    
    def __init__(self, dual_auth: bool = False, permissions: List[str] = None):
        self.dual_auth = dual_auth
        self.permissions = permissions or []
        super().__init__()
    
    def authenticate(self, request, token: str = None) -> Optional[User]:
        if self.dual_auth and token is None:
            return self._authenticate_api_key(request)
        
        return self._authenticate_jwt(token)
    
    def _authenticate_api_key(self, request) -> User:
        """Authenticate using API key from x-api-key header"""
        key = request.headers.get("x-api-key")
        if not key:
            return None
        
        try:
            api_key = verify_api_key(key)
            if not api_key:
                raise HttpError(401, "Invalid API key")
            
            if not api_key.is_active:
                raise HttpError(401, "API key has been revoked")
            
            if hasattr(api_key, 'expires_at') and api_key.expires_at and api_key.expires_at < timezone.now():
                raise HttpError(401, "API key has expired")

            if self.permissions:
                missing_perms = set(self.permissions) - set(api_key.permissions)
                if missing_perms:
                    perm_name = missing_perms.pop()
                    raise HttpError(403, f"API key lacks required permission: {perm_name}")
            
            user = APIKey.objects.get(key_hash__startswith=key[:10]).user
            return user
            
        except APIKey.DoesNotExist:
            raise HttpError(401, "Invalid API key")
    
    def _authenticate_jwt(self, token: str) -> Optional[User]:
        """Authenticate using JWT token"""
        if not token:
            return None
        
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            
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
        

def create_access_token(user: User) -> str:
    """Create access token (1 hour expiry)"""
    payload = {
        "user_id": str(user.id),
        "email": user.email,
        "exp": timezone.now() + timedelta(hours=1),
        "iat": timezone.now(),
        "type": "access"
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_refresh_token(user: User) -> str:
    """Create refresh token (7 days expiry)"""
    payload = {
        "user_id": str(user.id),
        "exp": timezone.now() + timedelta(days=7),
        "iat": timezone.now(),
        "type": "refresh"
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_tokens_for_user(user: User) -> dict:
    """Create both access and refresh tokens"""
    return {
        "access": create_access_token(user),
        "refresh": create_refresh_token(user)
    }


def refresh_access_token(refresh_token: str) -> Optional[str]:
    """Generate new access token from refresh token"""
    try:
        payload = jwt.decode(
            refresh_token,
            settings.SECRET_KEY,
            algorithms=["HS256"]
        )
        
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
