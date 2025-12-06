from django.conf import settings

class GoogleOAuthConfig:
    CLIENT_ID = settings.GOOGLE_OAUTH_CLIENT_ID
    CLIENT_SECRET = settings.GOOGLE_OAUTH_CLIENT_SECRET
    REDIRECT_URI = settings.GOOGLE_OAUTH_REDIRECT_URI
    SCOPES = ["openid", "email", "profile"]
    AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URI = "https://oauth2.googleapis.com/token"