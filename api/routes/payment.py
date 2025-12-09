"""
Payment-related endpoints
"""
import json
import logging

from django.conf import settings
from django.http import HttpRequest
from django.views.decorators.csrf import csrf_exempt
from ninja import Router, Query
from ninja.responses import Response
from paystack import PaystackClient, APIError

from api.utils import JWTAuth, verify_paystack_signature
from api.models import Transaction
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

router = Router()

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)

@router.post(
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


@router.post(
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


@router.get(
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