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
from api.schemas import PaymentInitiateRequest, PaymentInitiateResponse, TransactionStatusResponse

logger = logging.getLogger(__name__)

api = NinjaAPI(urls_namespace="payd_api")
auth_router = Router()
api.add_router("/auth", auth_router, tags=["Authentication"])

payments_router = Router()
api.add_router("/payments", payments_router, tags=["Payments"])

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)

@auth_router.get("/google", url_name="google-login")
def google_login(request):
    if not GoogleOAuthConfig.CLIENT_ID or not GoogleOAuthConfig.CLIENT_SECRET:
        return Response({"error": "OAuth not configured"}, status=500)

    params = {
        "client_id": GoogleOAuthConfig.CLIENT_ID,
        "redirect_uri": GoogleOAuthConfig.REDIRECT_URI,
        "scope": " ".join(GoogleOAuthConfig.SCOPES),
        "response_type": "code",
        "access_type": "offline",
    }

    auth_url = f"{GoogleOAuthConfig.AUTH_URI}?{urlencode(params)}"
    return redirect(auth_url)


@auth_router.get("/google/callback", url_name="google-callback")
def google_callback(request):
    code = request.GET.get("code")

    if not code:
        return Response({"error": "missing code"}, status=400)

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
            return Response({"error": "invalid code"}, status=401)

        token_data = token_response.json()
        access_token = token_data.get("access_token")

        userinfo_response = requests.get(
            GoogleOAuthConfig.USERINFO_URI,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        if userinfo_response.status_code != 200:
            return Response({"error": "provider error"}, status=500)

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

        return Response(
            {
                "user_id": str(user.id),
                "email": user.email,
                "name": user.get_full_name(),
            }, 
            status=200
        )

    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        return Response({"error": "provider error"}, status=500)
    
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
            return Response({
                "reference": existing_transaction.reference,
                "authorization_url": existing_transaction.authorization_url,
            }, status=201)

        data, meta = paystack_client.transactions.initialize(
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

        return Response({
            "reference": transaction.reference,
            "authorization_url": transaction.authorization_url,
        }, status=201)

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return Response({"error": str(e)}, status=400)

    except APIError as e:
        logger.error(f"Paystack API error: {e.message}")
        return Response({"error": "payment initiation failed"}, status=402)

    except Exception as e:
        logger.error(f"Payment initiation error: {str(e)}")
        return Response({"error": "An error occurred while initiating payment"}, status=500)
    
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
        logger.warning("Webhook received without signature")
        return Response({"error": "invalid signature"}, status=400)
    
    payload = request.body
    
    if not verify_paystack_signature(payload, signature):
        logger.warning("Webhook signature verification failed")
        return Response({"error": "invalid signature"}, status=400)
    
    try:
        event = json.loads(payload.decode('utf-8'))
        event_type = event.get("event")
        data = event.get("data", {})
        
        logger.info(f"Webhook event received: {event_type}")
        
        if event_type == "charge.success":
            reference = data.get("reference")
            status = data.get("status")
            paid_at = data.get("paid_at")
            
            if not reference:
                logger.warning("Webhook missing transaction reference")
                return Response({"status": True}, status=200)
            
            try:
                transaction = Transaction.objects.get(reference=reference)
                
                if status == "success":
                    transaction.status = Transaction.Status.SUCCESS
                    transaction.paid_at = paid_at
                elif status == "failed":
                    transaction.status = Transaction.Status.FAILED
                else:
                    transaction.status = Transaction.Status.PENDING
                
                transaction.save()
                logger.info(f"Transaction {reference} updated to {transaction.status}")
                
            except Transaction.DoesNotExist:
                logger.warning(f"Transaction {reference} not found in database")
                return Response({"status": True}, status=200)
        
        return Response({"status": True}, status=200)
        
    except json.JSONDecodeError:
        logger.error("Failed to parse webhook JSON payload")
        return Response({"error": "invalid payload"}, status=400)
        
    except Exception as e:
        logger.error(f"Webhook processing error: {str(e)}")
        return Response({"error": "internal server error"}, status=500)
    
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
        return Response({"error": "Invalid transaction reference format"}, status=400)

    try:
        transaction = Transaction.objects.get(reference=reference)
    except Transaction.DoesNotExist:
        return Response({"error": "transaction not found"}, status=404)

    if refresh:
        try:
            data, meta = paystack_client.transactions.verify(reference=reference)

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

    return Response({
        "reference": transaction.reference,
        "status": transaction.status,
        "amount": transaction.amount,
        "paid_at": transaction.paid_at,
        "currency": transaction.currency,
    }, status=200)