"""
Wallet-related endpoints
"""
# import logging

# from ninja import Router

# from api.schemas import Wallet
# from api.utils import JWTAuth

# logger = logging.getLogger(__name__)

# router = Router()


# @router.get("", response=Wallet, auth=JWTAuth())
# def get_wallet(request):
#     """
#     Get wallet details for the authenticated user.
#     """
#     user = request.auth
#     wallet = user.wallet
#     return wallet
