"""
Payment-related endpoints
"""

import json
import logging

from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from ninja import Router
from ninja.responses import Response
from paystack import PaystackClient

from api.utils import verify_paystack_signature
from api.models import Transaction
from api.exceptions import (
    InvalidRequestException,
)

logger = logging.getLogger(__name__)

router = Router()

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)


@router.post(
    "/paystack",
    response={200: dict, 400: dict, 500: dict},
    url_name="paystack-webhook",
    auth=None,
    include_in_schema=False,
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
                    transaction.updated_at = timezone.now()
                    if transaction.type == Transaction.Type.DEPOSIT:
                        wallet = transaction.wallet
                        current_wallet_balance = wallet.balance
                        wallet.balance = current_wallet_balance + transaction.amount
                        wallet.updated_at = timezone.now()
                        wallet.save()
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
