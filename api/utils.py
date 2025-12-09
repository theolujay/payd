import hmac
import hashlib
from typing import Optional
from datetime import datetime, timedelta
from django.utils import timezone

import jwt
from django.conf import settings
from ninja.security import HttpBearer

from api.models import User

class JWTAuth(HttpBearer):
    """JWT Authentication"""
    
    def authenticate(self, request, token: str) -> Optional[User]:
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
            
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, User.DoesNotExist):
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
