import json
import logging
import requests
from urllib.parse import urlencode

from django.conf import settings
from django.http import HttpRequest
from django.views.decorators.csrf import csrf_exempt
from ninja import NinjaAPI, Router, Query
from ninja.responses import Response
from paystack import PaystackClient, APIError

from api.auth import JWTAuth, create_tokens_for_user, refresh_access_token
from api.utils import GoogleOAuthConfig, verify_paystack_signature
from api.models import Transaction, User
from api.schemas import (
    PaymentInitiateRequest,
    PaymentInitiateResponse,
    TransactionStatusResponse,
    GoogleAuthURLResponse,
    TokenResponse,
    RefreshTokenRequest,
)
from api.exceptions import (
    api_exception_handler,
    InvalidRequestException,
    IntegrationException,
    NotFoundException,
)

logger = logging.getLogger(__name__)

api = NinjaAPI(urls_namespace="payd_api", title="PaydAPI", version="0.1.0")
api.add_exception_handler(Exception, api_exception_handler)


@api.get("/", summary="API Root / Health Check")
def root(request):
    return {"message": "Welcome to Payd API!"}


auth_router = Router()
api.add_router("/auth", auth_router, tags=["Authentication"])

payments_router = Router()
api.add_router("/payments", payments_router, tags=["Payments"])

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)

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

@payments_router.post(
    "/paystack/initiate",
    response={201: PaymentInitiateResponse},
    url_name="paystack-initiate",
    auth=JWTAuth(),
)
def initiate_paystack_payment(request, payload: PaymentInitiateRequest):
    """
    Initiate payment - requires JWT authentication.
    Use: Authorization: Bearer <your_access_token>
    """
    user = request.auth

    try:
        existing_transaction = Transaction.objects.filter(
            amount=payload.amount, status=Transaction.Status.PENDING, user=user
        ).first()

        if existing_transaction:
            logger.info(
                f"Found existing pending transaction for amount {payload.amount}"
            )
            return Response(
                {
                    "reference": existing_transaction.reference,
                    "authorization_url": existing_transaction.authorization_url,
                },
                status=201,
            )
            
        data, _ = paystack_client.transactions.initialize(
            amount=payload.amount,
            email=user.email,
            currency="NGN",
        )

        transaction = Transaction.objects.create(
            reference=data["reference"],
            amount=payload.amount,
            currency="NGN",
            status=Transaction.Status.PENDING,
            authorization_url=data["authorization_url"],
            user=user,
        )

        logger.info(f"Payment initiated with reference {transaction.reference}")

        return Response(
            {
                "reference": transaction.reference,
                "authorization_url": transaction.authorization_url,
            },
            status=201,
        )

    except ValueError as e:
        raise InvalidRequestException(str(e))

    except APIError as e:
        logger.error(f"Paystack API error: {e.message}")
        raise IntegrationException("Payment initiation failed")


@payments_router.post(
    "/paystack/webhook",
    response={200: dict, 400: dict, 500: dict},
    url_name="paystack-webhook",
    auth=None,
)
@csrf_exempt
def paystack_webhook(request: HttpRequest):
    """Handle Paystack webhook notifications"""
    signature = request.headers.get("x-paystack-signature")
    if not signature:
        logger.warning("Missing Paystack signature header")
        raise InvalidRequestException("Missing signature")

    payload = request.body
    if not verify_paystack_signature(payload, signature):
        logger.warning("Invalid Paystack signature")
        raise InvalidRequestException("Invalid signature")

    try:
        event = json.loads(payload.decode("utf-8"))
        event_type = event.get("event")
        data = event.get("data", {})

        logger.info(f"Webhook event received: {event_type}")

        if event_type == "charge.success":
            reference = data.get("reference")
            if not reference:
                logger.warning("Webhook missing transaction reference")
                return Response({"status": True}, status=200)

            try:
                transaction = Transaction.objects.get(reference=reference)
                status = data.get("status")

                if status == "success":
                    transaction.status = Transaction.Status.SUCCESS
                    transaction.paid_at = data.get("paid_at")
                elif status == "failed":
                    transaction.status = Transaction.Status.FAILED
                else:
                    transaction.status = Transaction.Status.PENDING

                transaction.save()
                logger.info(f"Transaction {reference} updated to {transaction.status}")

            except Transaction.DoesNotExist:
                logger.warning(f"Transaction {reference} not found in database")

        return Response({"status": True}, status=200)

    except json.JSONDecodeError:
        raise InvalidRequestException("Invalid JSON payload")


@payments_router.get(
    "/{reference}/status",
    response={200: TransactionStatusResponse},
    url_name="transaction-status",
    auth=JWTAuth(),
)
def get_transaction_status(
    request,
    reference: str,
    refresh: bool = Query(False, description="Refresh from Paystack API"),
):
    """
    Get transaction status - requires JWT authentication.
    Use: Authorization: Bearer <your_access_token>
    """
    if not reference or len(reference) < 5:
        raise InvalidRequestException("Invalid transaction reference format")

    try:
        transaction = Transaction.objects.get(reference=reference)
    except Transaction.DoesNotExist:
        raise NotFoundException("Transaction not found")

    # Verify user owns this transaction
    user = request.auth
    if transaction.user and transaction.user.id != user.id:
        raise NotFoundException("Transaction not found")

    if refresh:
        try:
            data, _ = paystack_client.transactions.verify(reference=reference)
            paystack_status = data.get("status")

            if paystack_status == "success":
                transaction.status = Transaction.Status.SUCCESS
                transaction.paid_at = data.get("paid_at")
            elif paystack_status == "failed":
                transaction.status = Transaction.Status.FAILED
            else:
                transaction.status = Transaction.Status.PENDING

            transaction.save()
            logger.info(f"Transaction {reference} refreshed from Paystack")

        except APIError as e:
            logger.warning(
                f"Failed to refresh transaction {reference} from Paystack: {e.message}"
            )
        except Exception as e:
            logger.error(f"Error refreshing transaction {reference}: {str(e)}")

    return Response(
        {
            "reference": transaction.reference,
            "status": transaction.status,
            "amount": transaction.amount,
            "paid_at": transaction.paid_at,
            "currency": transaction.currency,
        },
        status=200,
    )