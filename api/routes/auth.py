"""
Auth-related endpoints.
"""

import logging
from typing import List
from uuid import UUID
from django.db import DatabaseError
from django.utils import timezone
from datetime import timedelta
import requests
from urllib.parse import urlencode

from ninja import Router, Path
from ninja.pagination import paginate
from ninja.responses import Response

from api.utils import (
    API_KEY_HEADER_SPEC,
    GoogleOAuthConfig,
    JWTAuth,
    create_tokens_for_user,
    refresh_access_token,
    generate_api_key,
)
from api.models import User, Wallet, APIKey
from api.schemas import (
    GoogleAuthURLResponse,
    KeysListSchema,
    RolloverAPIKeyRequest,
    TokenResponse,
    RefreshTokenRequest,
    CreateAPIKeysRequest,
)
from api.exceptions import (
    InvalidRequestException,
    IntegrationException,
)

logger = logging.getLogger(__name__)

expiry_refs = {
    "1H": timedelta(hours=1),
    "1D": timedelta(days=1),
    "1M": timedelta(days=30),
    "1Y": timedelta(weeks=52),
}

router = Router()


@router.get(
    "/google",
    response=GoogleAuthURLResponse,
    url_name="google-login",
    auth=None,
    summary="Get Google OAuth URL",
    description="""
    Returns the Google OAuth authorization URL for user authentication.
    
    How to use:
    1. Call this endpoint to get the authorization URL
    2. Redirect the user to this URL in their browser
    3. User signs in with Google and grants permissions
    4. Google redirects back to the callback URL with an authorization code
    5. The callback endpoint exchanges the code for JWT tokens
    
    Authentication: None required
    """,
)
def google_login(request):
    """Generate Google OAuth authorization URL."""
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

    return {"auth_url": auth_url}


@router.get(
    "/google/callback",
    response=TokenResponse,
    url_name="google-callback",
    auth=None,
    include_in_schema=False,
)
def google_callback(request):
    """
    Exchange Google OAuth code for JWT tokens.
    
    This endpoint is called automatically after Google authentication.
    Creates or updates user account and returns access/refresh tokens.
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
        return Response(
            {"detail": "Unable to connect to Google OAuth service"}, status=502
        )

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
        return Response(
            {"detail": "Unexpected error creating/updating user"}, status=503
        )

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
                "picture": user.picture_url,
            },
        },
        status=201 if user_created else 200,
    )


@router.post(
    "/token/refresh",
    response=dict,
    url_name="token-refresh",
    auth=None,
    summary="Refresh Access Token",
    description="""
    Generate a new access token using a valid refresh token.
    
    When to use: Call this endpoint when your access token expires.
    
    Authentication: None required, but you must provide a valid refresh token in the request body.
    
    Response: Returns a new access token that you should use for subsequent API calls.
    """,
)
def refresh_token(request, payload: RefreshTokenRequest):
    """Exchange refresh token for new access token."""
    new_access_token = refresh_access_token(payload.refresh)

    if not new_access_token:
        raise InvalidRequestException("Invalid or expired refresh token")

    return {"access": new_access_token}


@router.post(
    "/keys/create",
    response=dict,
    url_name="keys-create",
    auth=JWTAuth(),
    summary="Create API Key",
    description="""
    Create a new API key with specified permissions and expiration period.
    
    Limits: Maximum 5 active API keys per user.
    
    Permissions:
    - read: View wallet balance and transaction history
    - deposit: Initiate deposits into wallet
    - transfer: Transfer funds between wallets
    
    Expiration options:
    - 1H: 1 hour
    - 1D: 1 day
    - 1M: 30 days
    - 1Y: 1 year
    
    Security: The API key is only shown once upon creation. Store it securely.
    
    Authentication: Requires JWT token in Authorization: Bearer <token> header.
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
def create_api_key(request, payload: CreateAPIKeysRequest):
    """Create new API key for authenticated user (max 5 active keys)."""
    user = request.auth
    api_keys = APIKey.objects.filter(user=user, is_active=True)
    num_of_api_keys = api_keys.count()
    if num_of_api_keys >= 5:
        return Response({"detail": "Maximum 5 active API keys allowed"}, status=403)

    try:
        plain_key, hashed_key, lookup_hint = generate_api_key()
        new_api_key = APIKey.objects.create(
            user=user,
            name=payload.name,
            key_hash=hashed_key,
            lookup_hint=lookup_hint,
            permissions=payload.permissions,
            expires_at=timezone.now() + expiry_refs[payload.expiry],
            is_active=True,
        )
        return Response(
            {"api_key": plain_key, "expires_at": new_api_key.expires_at}, status=201
        )
    except DatabaseError as e:
        logger.error(f"Database error during api_key creation: {str(e)}")
        return Response({"detail": "Unexpected error creating api_key"}, status=503)


@router.post(
    "/keys/rollover",
    response=dict,
    url_name="keys-rollover",
    auth=JWTAuth(),
    summary="Rollover Expired API Key",
    description="""
    Replace an expired API key with a new one while preserving its name and permissions.
    
    Use case: When an API key expires, use this endpoint to generate a replacement without losing the key's configuration.
    
    Requirements:
    - Original key must be expired
    - Must not exceed 5 active keys limit
    
    What's preserved: Name and permissions from the old key
    
    What's new: Key value and expiration date
    
    Authentication: Requires JWT token in Authorization: Bearer <token> header.
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
def rollover_expired_api_key(request, payload: RolloverAPIKeyRequest):
    """Generate new API key from expired key, maintaining original settings."""
    user = request.auth
    
    try:
        old_api_key = APIKey.objects.get(id=payload.expired_key_id, user=user)
    except APIKey.DoesNotExist:
        return Response({"detail": "API key not found"}, status=404)
    
    if not old_api_key.expires_at < timezone.now():
        return Response(
            {"detail": "Key is not expired. Cannot rollover."}, status=403
        )
    
    api_keys = APIKey.objects.filter(user=user, is_active=True)
    if api_keys.count() >= 5:
        return Response({"detail": "Maximum 5 active API keys allowed"}, status=403)
    
    try:
        plain_key, hashed_key, lookup_hint = generate_api_key()
        new_api_key = APIKey.objects.create(
            user=user,
            name=old_api_key.name,
            key_hash=hashed_key,
            lookup_hint=lookup_hint,
            permissions=old_api_key.permissions,
            expires_at=timezone.now() + expiry_refs[payload.expiry],
        )
        return Response(
            {"api_key": plain_key, "expires_at": new_api_key.expires_at}, status=201
        )
    except DatabaseError as e:
        logger.error(f"Database error during api_key rollover: {str(e)}")
        return Response({"detail": "Unexpected error rolling over api_key"}, status=503)


@router.post(
    "/keys/{key_id}/revoke",
    response=dict,
    url_name="keys-revoke",
    auth=JWTAuth(),
    summary="Revoke API Key",
    description="""
    Permanently deactivate an API key. This action cannot be undone.
    
    When to use:
    - Key has been compromised
    - Key is no longer needed
    - Replacing key with new one
    
    Effect: The key becomes immediately inactive and cannot be used for authentication.
    
    Note: This does not delete the key from the database, it only marks it as inactive.
    
    Authentication: Requires JWT token in Authorization: Bearer <token> header.
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
def revoke_api_key(
    request, key_id: UUID = Path(..., description="UUID of the API key to revoke")
):
    """Revoke (deactivate) an API key permanently."""
    user = request.auth
    
    try:
        api_key = APIKey.objects.get(id=key_id, user=user)
    except APIKey.DoesNotExist:
        return Response({"detail": "API key not found"}, status=404)

    if not api_key.is_active:
        return Response({"detail": "API key is already revoked"}, status=400)

    api_key.is_active = False
    api_key.revoked_at = timezone.now()
    api_key.save()

    return Response({"message": "API key revoked"}, status=200)


@router.get(
    "/keys",
    response=List[KeysListSchema],
    url_name="keys-list",
    auth=JWTAuth(),
    summary="List API Keys",
    description="""
    Retrieve all API keys (both active and revoked) for your account with pagination support.
    
    Returns: List of API keys showing:
    - Key ID and name
    - Active status
    - Permissions
    - Creation and expiration dates
    
    Note: The actual key values are not returned (only shown once during creation).
    
    Pagination: Use limit and offset query parameters to paginate results.
    
    Authentication: Requires JWT token in Authorization: Bearer <token> header.
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
@paginate
def list_api_keys(request):
    """List all API keys for authenticated user with pagination support."""
    user = request.auth
    return APIKey.objects.filter(user=user)

