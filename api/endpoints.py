
import logging
import requests
from urllib.parse import urlencode

from django.conf import settings
from django.shortcuts import redirect
from ninja import NinjaAPI, Router
from ninja.responses import Response


from api.utils import GoogleOAuthConfig
from api.models import User

logger = logging.getLogger(__name__)

api = NinjaAPI(urls_namespace="payd_api")
auth_router = Router()
api.add_router("/auth", auth_router, tags=["Authentication"])


@auth_router.get("/google", url_name="google-login")
def google_login(request):
    if not GoogleOAuthConfig.CLIENT_ID or not GoogleOAuthConfig.CLIENT_SECRET:
        return Response({"error": "OAuth not configured"}, status=500)

    params = {
        "client_id": GoogleOAuthConfig.CLIENT_ID,
        "redirect_uri": GoogleOAuthConfig.REDIRECT_URI,
        "scope": " ".join(GoogleOAuthConfig.SCOPES),
        "response_type": "code",
        "access_type": "offline",
    }

    auth_url = f"{GoogleOAuthConfig.AUTH_URI}?{urlencode(params)}"
    return redirect(auth_url)


@auth_router.get("/google/callback", url_name="google-callback")
def google_callback(request):
    code = request.GET.get("code")

    if not code:
        return Response({"error": "missing code"}, status=400)

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
            return Response({"error": "invalid code"}, status=401)

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        userinfo_response = requests.get(
            GoogleOAuthConfig.USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if userinfo_response.status_code != 200:
            return Response({"error": "provider error"}, status=500)

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

        return Response(
            {
                "user_id": str(user.id),
                "email": user.email,
                "name": user.get_full_name(),
            }, 
            status=200
        )

    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return Response({"error": "provider error"}, status=500)