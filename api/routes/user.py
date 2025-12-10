"""
User-related endpoints
"""

from ninja import Router
from api.utils import JWTAuth
from api.schemas import UserSchema

router = Router()


@router.get("/profile", response=UserSchema, auth=JWTAuth())
def get_user_profile(request):
    """
    Get the authenticated user's profile.
    Requires JWT authentication.
    Use:
        Authorization: Bearer <your_access_token>
    """
    return request.auth
