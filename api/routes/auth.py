"""
Auth-related endpoints.
"""
import logging
from django.db import DatabaseError
from django.utils import timezone
from datetime import datetime, timedelta
import requests
from urllib.parse import urlencode

from ninja import Router
from ninja.responses import Response

from api.utils import (
    GoogleOAuthConfig,
    JWTAuth,
    create_tokens_for_user,
    refresh_access_token,
    generate_api_key,
    verify_api_key,
)
from api.models import User, Wallet, APIKey
from api.schemas import (
    GoogleAuthURLResponse,
    TokenResponse,
    RefreshTokenRequest,
    CreateAPIKeysRequest,
)
from api.exceptions import (
    InvalidRequestException,
    IntegrationException,
)

logger = logging.getLogger(__name__)


router = Router()

@router.get(
    "/google",
    response=GoogleAuthURLResponse,
    url_name="google-login",
    auth=None,
)
def google_login(request):
    """
    Get Google OAuth URL for authentication.
    Copy the returned URL and open it in your browser to sign in.
    """
    if not GoogleOAuthConfig.CLIENT_ID or not GoogleOAuthConfig.CLIENT_SECRET:
        raise IntegrationException("OAuth not configured")

    params = {
        "client_id": GoogleOAuthConfig.CLIENT_ID,
        "redirect_uri": GoogleOAuthConfig.REDIRECT_URI,
        "scope": " ".join(GoogleOAuthConfig.SCOPES),
        "response_type": "code",
        "access_type": "offline",
    }

    auth_url = f"{GoogleOAuthConfig.AUTH_URI}?{urlencode(params)}"

    return {
        "auth_url": auth_url
    }


@router.get(
    "/google/callback",
    response=TokenResponse,
    url_name="google-callback",
    auth=None,
)
def google_callback(request):
    """
    Google OAuth callback - exchanges auth code for JWT tokens.
    After signing in with Google, you'll be redirected here.
    """
    code = request.GET.get("code")
    if not code:
        raise InvalidRequestException("Missing authorization code")

    try:
        token_response = requests.post(
            GoogleOAuthConfig.TOKEN_URI,
            data={
                "code": code,
                "client_id": GoogleOAuthConfig.CLIENT_ID,
                "client_secret": GoogleOAuthConfig.CLIENT_SECRET,
                "redirect_uri": GoogleOAuthConfig.REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if token_response.status_code != 200:
            raise IntegrationException("Invalid authorization code", status_code=401)

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        userinfo_response = requests.get(
            GoogleOAuthConfig.USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if userinfo_response.status_code != 200:
            raise IntegrationException("Failed to fetch user info from provider")

        user_data = userinfo_response.json()
        
    except ConnectionError:
        return Response({"detail": "Connection Error"}, status=500)
    except requests.RequestException as e:
        logger.error(f"OAuth request error: {str(e)}")
        return Response({"detail": "Unable to connect to Google OAuth service"}, status=502)

    try:
        user, user_created = User.objects.update_or_create(
            google_id=user_data["id"],
            defaults={
                "email": user_data["email"],
                "username": user_data["email"],
                "first_name": user_data.get("given_name", ""),
                "last_name": user_data.get("family_name", ""),
                "picture_url": user_data.get("picture", ""),
                "is_email_verified": True,
            },
        )
        wallet, wallet_created = Wallet.objects.get_or_create(user=user)
        if wallet_created and not user_created:
            logger.warning(f"Late wallet creation for user {user.email}")
                    
    except DatabaseError as e:
        logger.error(f"Database error during user/wallet creation: {str(e)}")
        return Response({"detail": "Unexpected error creating/updating user"}, status=503)

    tokens = create_tokens_for_user(user)
    logger.info(f"User {user.email} authenticated successfully")

    return Response(
        {
            "access": tokens["access"],
            "refresh": tokens["refresh"],
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": user.get_full_name(),
                "picture": user.picture_url
            },
        },
        status=201 if user_created else 200
    )


@router.post(
    "/token/refresh",
    response=dict,
    url_name="token-refresh",
    auth=None,
)
def refresh_token(request, payload: RefreshTokenRequest):
    """
    Refresh access token using refresh token.
    """
    new_access_token = refresh_access_token(payload.refresh)
    
    if not new_access_token:
        raise InvalidRequestException("Invalid or expired refresh token")
    
    return {"access": new_access_token}

@router.post(
    "/keys/create",
    response=dict,
    url_name="keys-create",
    auth=JWTAuth(),
)
def create_api_keys(request, payload: CreateAPIKeysRequest):
    """
    Create API keys for the authenticated user
    """
    user = request.auth
    api_keys = APIKey.objects.filter(user=user, is_active=True)
    num_of_api_keys = api_keys.count()
    if num_of_api_keys >= 5:
        return Response(
            {
                "detail": "Maximum 5 active API keys allowed"
            },
            status=404
        )
        
    expiry_refs = {
        "1H": timezone.now() + timedelta(hours=1),
        "1D": timezone.now() + timedelta(days=1),
        "1M": timezone.now() + timedelta(days=30),
        "1Y": timezone.now() + timedelta(weeks=52)
    }
    
    try:
        plain_key, hashed_key = generate_api_key()
        new_api_key = APIKey.objects.create(
            user=user,
            name=payload.name,
            key_hash=hashed_key,
            permissions=payload.permissions,
            expires_at=expiry_refs[payload.expiry],
            is_active=True,
        )
        return Response(
            {
                "api_key": plain_key,
                "expires_at": new_api_key.expires_at
            },
            status=201            
        )
    except DatabaseError as e:
        logger.error(f"Database error during api_key creation: {str(e)}")
        return Response({"detail": "Unexpected error creating api_key"}, status=503)
