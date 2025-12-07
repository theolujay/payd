import hmac
import hashlib
from django.conf import settings


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
