"""
Auth-related endpoints.
"""
import logging
import requests
from urllib.parse import urlencode

from ninja import NinjaAPI, Router

from api.utils import (
    GoogleOAuthConfig,
    create_tokens_for_user,
    refresh_access_token,
)
from api.models import User
from api.schemas import (
    GoogleAuthURLResponse,
    TokenResponse,
    RefreshTokenRequest,
)
from api.exceptions import (
    api_exception_handler,
    InvalidRequestException,
    IntegrationException,
)

logger = logging.getLogger(__name__)

api = NinjaAPI(urls_namespace="payd_api", title="PaydAPI", version="0.1.0")
api.add_exception_handler(Exception, api_exception_handler)


auth_router = Router()
api.add_router("/auth", auth_router, tags=["Authentication"])

@auth_router.get(
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


@auth_router.get(
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
            raise IntegrationException("Invalid authorization code")

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        userinfo_response = requests.get(
            GoogleOAuthConfig.USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if userinfo_response.status_code != 200:
            raise IntegrationException("Failed to fetch user info from provider")

        user_data = userinfo_response.json()

        user, _ = User.objects.update_or_create(
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

        tokens = create_tokens_for_user(user)

        logger.info(f"User {user.email} authenticated successfully")

        return {
            "access": tokens["access"],
            "refresh": tokens["refresh"],
            "user": {
                "id": str(user.id),
                "email": user.email,
                "name": user.get_full_name(),
                "picture": user.picture_url,
            },
        }

    except requests.RequestException as e:
        logger.error(f"OAuth request error: {str(e)}")
        raise IntegrationException("Provider communication error")


@auth_router.post(
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