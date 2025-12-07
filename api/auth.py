import jwt
from datetime import datetime, timedelta
from typing import Optional, Any
from django.conf import settings
from django.contrib.auth import get_user_model
from ninja.security import HttpBearer

User = get_user_model()


class JWTAuth(HttpBearer):
    """JWT Authentication for Django Ninja"""
    
    def authenticate(self, request, token: str) -> Optional[Any]:
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


def create_access_token(user: Any) -> str:
    """Create access token (1 hour expiry)"""
    payload = {
        "user_id": str(user.id),
        "email": user.email,
        "exp": datetime.utcnow() + timedelta(hours=1),
        "iat": datetime.utcnow(),
        "type": "access"
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_refresh_token(user: Any) -> str:
    """Create refresh token (7 days expiry)"""
    payload = {
        "user_id": str(user.id),
        "exp": datetime.utcnow() + timedelta(days=7),
        "iat": datetime.utcnow(),
        "type": "refresh"
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def create_tokens_for_user(user: Any) -> dict:
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