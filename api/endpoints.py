import logging

from django.conf import settings
from django.shortcuts import redirect
from ninja import NinjaAPI, Router
from ninja.responses import Response
from urllib.parse import urlencode

from api.utils import GoogleOAuthConfig


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
        "access_type": "offline"
    }
    auth_url = f"{GoogleOAuthConfig.AUTH_URI}?{urlencode(params)}"
    return redirect(auth_url)
