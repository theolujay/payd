import json
import logging
import requests
from typing import Optional
from urllib.parse import urlencode

from django.conf import settings
from django.shortcuts import redirect
from django.http import HttpRequest
from django.views.decorators.csrf import csrf_exempt
from ninja import NinjaAPI, Router, Query
from ninja.responses import Response
from paystack import PaystackClient, APIError


from api.utils import GoogleOAuthConfig, verify_paystack_signature
from api.models import Transaction, User
from api.schemas import (
    PaymentInitiateRequest,
    PaymentInitiateResponse,
    TransactionStatusResponse,
)
from api.exceptions import (
    api_exception_handler,
    InvalidRequestException,
    IntegrationException,
    NotFoundException,
)

logger = logging.getLogger(__name__)

api = NinjaAPI(urls_namespace="payd_api")
api.add_exception_handler(Exception, api_exception_handler)

@api.get("/", summary="API Root / Health Check")
def root(request):
    return {"message": "Welcome to PayD API!"}

auth_router = Router()
api.add_router("/auth", auth_router, tags=["Authentication"])

payments_router = Router()
api.add_router("/payments", payments_router, tags=["Payments"])

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)


def get_google_auth_url():
    if not GoogleOAuthConfig.CLIENT_ID or not GoogleOAuthConfig.CLIENT_SECRET:
        raise IntegrationException("OAuth not configured")
    params = {
        "client_id": GoogleOAuthConfig.CLIENT_ID,
        "redirect_uri": GoogleOAuthConfig.REDIRECT_URI,
        "scope": " ".join(GoogleOAuthConfig.SCOPES),
        "response_type": "code",
        "access_type": "offline",
    }
    return f"{GoogleOAuthConfig.AUTH_URI}?{urlencode(params)}"


def get_google_token(code: str) -> dict:
    response = requests.post(
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
    if response.status_code != 200:
        raise IntegrationException("Invalid authorization code")
    return response.json()


def get_google_user_info(access_token: str) -> dict:
    response = requests.get(
        GoogleOAuthConfig.USERINFO_URI,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if response.status_code != 200:
        raise IntegrationException("Failed to fetch user info from provider")
    return response.json()


@auth_router.get("/google", url_name="google-login")
def google_login(request):
    auth_url = get_google_auth_url()
    return redirect(auth_url)


@auth_router.get("/google/callback", url_name="google-callback")
def google_callback(request):
    code = request.GET.get("code")
    if not code:
        raise InvalidRequestException("Missing authorization code")

    token_data = get_google_token(code)
    access_token = token_data.get("access_token")
    if not access_token:
        raise IntegrationException("Access token not found in provider response")

    user_data = get_google_user_info(access_token)
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

    logger.info(f"User {user.email} authenticated successfully")
    return Response(
        {
            "user_id": str(user.id),
            "email": user.email,
            "name": user.get_full_name(),
        },
        status=200,
    )


@payments_router.post(
    "/paystack/initiate",
    response={201: PaymentInitiateResponse, 400: dict, 402: dict, 500: dict},
    url_name="paystack-initiate",
)
def initiate_paystack_payment(request, payload: PaymentInitiateRequest):
    try:
        existing_transaction = Transaction.objects.filter(
            amount=payload.amount, status=Transaction.Status.PENDING
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
            email=payload.email or "[email protected]",
            currency="NGN",
        )

        transaction = Transaction.objects.create(
            reference=data["reference"],
            amount=payload.amount,
            currency="NGN",
            status=Transaction.Status.PENDING,
            authorization_url=data["authorization_url"],
            user=None,
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
    signature = request.headers.get("x-paystack-signature")
    if not signature:
        raise InvalidRequestException("Invalid signature")

    payload = request.body
    if not verify_paystack_signature(payload, signature):
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
    response={200: TransactionStatusResponse, 400: dict, 404: dict},
    url_name="transaction-status",
)
def get_transaction_status(
    request,
    reference: str,
    refresh: bool = Query(False, description="Refresh from Paystack API"),
):
    if not reference or len(reference) < 5:
        raise InvalidRequestException("Invalid transaction reference format")

    try:
        transaction = Transaction.objects.get(reference=reference)
    except Transaction.DoesNotExist:
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
