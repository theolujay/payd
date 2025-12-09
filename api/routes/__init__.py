from ninja import NinjaAPI
from api.exceptions import api_exception_handler
from . import auth, payment, wallet

api = NinjaAPI(urls_namespace="payd_api", title="PaydAPI", version="0.1.0")
api.add_exception_handler(Exception, api_exception_handler)

api.add_router("auth", auth.router, tags=["Authentication"])
api.add_router("payment", payment.router, tags=["Payments"])
# api.add_router("wallet", wallet.router, tags=["Wallet"])
