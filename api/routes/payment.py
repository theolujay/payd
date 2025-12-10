"""
Payment-related endpoints
"""
import json
import logging

from django.conf import settings
from django.http import HttpRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from ninja import Router, Query
from ninja.responses import Response
from paystack import PaystackClient, APIError

from api.utils import JWTAPIKeyAuth, verify_paystack_signature
from api.models import Transaction, Wallet
from api.schemas import (
    PaymentInitiateResponse,
    TransactionStatusResponse,
    WalletDepositRequest,
)
from api.exceptions import (
    InvalidRequestException,
    IntegrationException,
    NotFoundException,
)

logger = logging.getLogger(__name__)

router = Router()

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)

@router.post(
    "/wallet/deposit",
    response={201: PaymentInitiateResponse},
    url_name="wallet-deposit",
    auth=JWTAPIKeyAuth(dual_auth=True, permissions=["deposit"]),
)
def wallet_deposit_with_paystack(request, payload: WalletDepositRequest):
    """
    Make wallet deposit with Paystack by  initiatiaing payment
    Requires JWT authentication OR API key with 'deposit' permission.
    Use:
        Authorization: Bearer <your_access_token> (for JWT auth)
        OR
        X-API-Key: <api_key> (for API key auth)        
    """
    user = request.auth

    try:
        user_wallet = Wallet.objects.get(user=user)
        existing_transaction = Transaction.objects.filter(
            amount=payload.amount,
            wallet=user_wallet,
            status=Transaction.Status.PENDING,
            type=Transaction.Type.DEPOSIT
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
            
        payment_data, _ = paystack_client.transactions.initialize(
            amount=payload.amount,
            email=user.email,
            currency="NGN",
        )
    except Wallet.DoesNotExist:
        logger.info(f"Wallet not found for user: {user.email}")
        return Response(
            {
                "detail": "Wallet not found for user"
            },
            status=503
        )
    except ValueError as e:
        raise InvalidRequestException(str(e))
    
    try:
        transaction = Transaction.objects.create(
            wallet=user_wallet,
            type=Transaction.Type.DEPOSIT,
            amount=payload.amount,
            reference=payment_data["reference"],
            status=Transaction.Status.PENDING,
            currency="NGN",
            authorization_url=payment_data["authorization_url"],
        )

        logger.info(f"Payment initiated with reference {transaction.reference}")

        return Response(
            {
                "reference": transaction.reference,
                "authorization_url": transaction.authorization_url,
            },
            status=201,
        )
    except APIError as e:
        transaction.type = Transaction.Type.FAILED
        transaction.updated_at = timezone.now()
        transaction.save()
        
        logger.error(f"Paystack API error: {e.message}")
        
        return Response(
            {
                "detail": "Payment initiation failed"
            },
            402
        )

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


@router.get(
    "transaction/{reference}/status",
    response=dict,
    url_name="transaction-status",
    auth=JWTAPIKeyAuth(dual=True, permissions=["read"]),
)
def get_transaction_status(
    request,
    reference: str,
    refresh: bool = Query(False, description="Refresh from Paystack API"),
):
    """
    Get transaction status - requires JWT authentication.
    Requires JWT authentication OR API key with 'read' permission.
    Use:
        Authorization: Bearer <your_access_token> (for JWT auth)
        OR
        X-API-Key: <api_key> (for API key auth)    
    """
    if not reference or len(reference) < 5:
        return Response(
            {
                "detail": "Invalid transaction reference format"
            },
            status=400
        )

    try:
        transaction = Transaction.objects.get(reference=reference)
    except Transaction.DoesNotExist:
        return Response(
            {
                "detail": "Transaction not found"
            },
            status=404
        )

    user = request.auth
    if transaction.user and transaction.user.id != user.id:
        return Response(
            {
                "detail": "Transaction not found"
            },
            status=404
        )

    if refresh:
        try:
            data, _ = paystack_client.transactions.verify(reference=reference)
            transaction_status = data.get("status")
            transaction_amount = data.get("amount")
            

            logger.info(f"Transaction {reference} fetched from Paystack")
            return Response(
                {
                    "reference": reference,
                    "status": transaction_status,
                    "amount": transaction_amount
                }
            )

        except APIError as e:
            logger.warning(
                f"Failed to get status for transaction {reference} from Paystack: {e.message}"
            )
            return Response(
                {
                    "detail": "Failed to get transaction status"
                },
                status=503
            )
        except Exception as e:
            logger.error(f"Error refreshing transaction {reference}: {str(e)}")
            return Response(
                {
                    "detail": "Failed to get transaction status"
                },
                status=503
            )

    return Response(
        {
            "reference": transaction.reference,
            "status": transaction.status,
            "amount": transaction.amount,
        },
        status=200,
    )
    
@router.get(
    "wallet/balance",
    response=dict,
    url_name="wallet-balance",
    auth=JWTAPIKeyAuth(dual=True, permissions=["read"])
)
def get_wallet_balance(request):
    user = request.auth
    try:
        logger.info(f"Wallet balance request by usr: {user.email}")
        user_wallet = Wallet.objects.get(user=user)
        return Response(
            {
                "balance": user_wallet.balance
            },
            status=200
        )
    except Wallet.DoesNotExist:
        logger.warning(f"Wallet balance request by usr: {user.email}")
        return Response(
            {
                "detail": "Wallet does not exist"
            },
            status=404
        )
    