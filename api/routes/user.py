"""
User-related endpoints
"""

from ninja import Router
from api.utils import JWTAuth
from api.schemas import UserSchema

router = Router()


@router.get(
    "/profile",
    response=UserSchema,
    auth=JWTAuth(),
    summary="Get User Profile",
    description="Retrieve your profile information including wallet number.",
)
def get_user_profile(request):
    """Get authenticated user's profile and wallet information."""
    return request.auth