from ninja import NinjaAPI
from api.exceptions import api_exception_handler
from . import auth, wallet, webhooks, user

api = NinjaAPI(urls_namespace="payd_api", title="Payd API", version="0.1.1")
api.add_exception_handler(Exception, api_exception_handler)

api.add_router("auth", auth.router, tags=["Auth & Keys"])
api.add_router("wallet", wallet.router, tags=["Wallet"])
api.add_router("user", user.router, tags=["User"])
api.add_router("webhooks", webhooks.router, tags=["Webhooks"])