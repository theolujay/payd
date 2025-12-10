"""
Payment-related endpoints
"""

import logging
from typing import List

from django.conf import settings
from django.db import DatabaseError, transaction
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from ninja import Router, Query
from ninja.responses import Response
from ninja.pagination import paginate
from paystack import PaystackClient, APIError

from api.utils import JWTAPIKeyAuth
from api.models import Transaction, Wallet
from api.schemas import (
    PaymentInitiateResponse,
    WalletToWalletTransferRequest,
    WalletDepositRequest,
    TransactionHistorySchema,
)
from api.exceptions import (
    InvalidRequestException,
)

logger = logging.getLogger(__name__)

router = Router()

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)


@router.post(
    "/deposit",
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
            type=Transaction.Type.DEPOSIT,
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
        return Response({"detail": "Wallet not found for user"}, status=503)
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

        return Response({"detail": "Payment initiation failed"}, 402)


@router.get(
    "/transaction/{reference}/status",
    response=dict,
    url_name="transaction-status",
    auth=JWTAPIKeyAuth(dual_auth=True, permissions=["read"]),
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
        return Response({"detail": "Invalid transaction reference format"}, status=400)

    try:
        transaction = Transaction.objects.get(reference=reference)
    except Transaction.DoesNotExist:
        return Response({"detail": "Transaction not found"}, status=404)

    user = request.auth
    if transaction.user and transaction.user.id != user.id:
        return Response({"detail": "Transaction not found"}, status=404)

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
                    "amount": transaction_amount,
                }
            )

        except APIError as e:
            logger.warning(
                f"Failed to get status for transaction {reference} from Paystack: {e.message}"
            )
            return Response({"detail": "Failed to get transaction status"}, status=503)
        except Exception as e:
            logger.error(f"Error refreshing transaction {reference}: {str(e)}")
            return Response({"detail": "Failed to get transaction status"}, status=503)

    return Response(
        {
            "reference": transaction.reference,
            "status": transaction.status,
            "amount": transaction.amount,
        },
        status=200,
    )


@router.get(
    "/balance",
    response=dict,
    url_name="wallet-balance",
    auth=JWTAPIKeyAuth(dual_auth=True, permissions=["read"]),
)
def get_wallet_balance(request):
    user = request.auth
    try:
        logger.info(f"Wallet balance request by usr: {user.email}")
        user_wallet = Wallet.objects.get(user=user)
        return Response({"balance": user_wallet.balance}, status=200)
    except Wallet.DoesNotExist:
        logger.warning(f"Wallet balance request by usr: {user.email}")
        return Response({"detail": "Wallet does not exist"}, status=404)


@router.post(
    "/transfer",
    response=dict,
    url_name="wallet-transfer",
    auth=JWTAPIKeyAuth(dual_auth=True, permissions=["transfer"]),
)
def wallet_to_wallet_transfer(request, payload: WalletToWalletTransferRequest):
    user = request.auth
    amount = payload.amount
    recipient_wallet_id = payload.wallet_number

    if amount <= 0:
        return Response({"detail": "Amount must be greater than 0"}, status=400)

    try:
        with transaction.atomic():
            user_wallet = Wallet.objects.select_for_update().get(
                user=user
            )  # this is to lock rows to prevent race conditions

            if str(user_wallet.id) == str(recipient_wallet_id):
                return Response(
                    {"detail": "Cannot transfer to your own wallet"}, status=400
                )
            try:
                recipient_wallet = Wallet.objects.select_for_update().get(  # same idea to prevent race conditions
                    id=recipient_wallet_id
                )
            except ObjectDoesNotExist:
                return Response({"detail": "Recipient wallet not found"}, status=404)

            if user_wallet.balance < amount:
                return Response({"detail": "Insufficient balance"}, status=400)

            # create transaction records and link them
            transfer_out = Transaction.objects.create(
                wallet=user_wallet,
                type=Transaction.Type.TRANSFER_OUT,
                amount=amount,
                status=Transaction.Status.SUCCESS,
            )

            transfer_in = Transaction.objects.create(
                wallet=recipient_wallet,
                type=Transaction.Type.TRANSFER_IN,
                amount=amount,
                status=Transaction.Status.SUCCESS,
            )

            transfer_out.metadata = {"transfer_to_id": transfer_in.id}
            transfer_in.metadata = {"transfer_from_id": transfer_out.id}
            transfer_out.save()
            transfer_in.save()

            # update balances
            user_wallet.balance -= amount
            recipient_wallet.balance += amount
            user_wallet.updated_at = timezone.now()
            recipient_wallet.updated_at = timezone.now()
            user_wallet.save()
            recipient_wallet.save()

        # transaction committed successfully
        return Response(
            {"status": "success", "message": "Transfer completed"}, status=200
        )

    except DatabaseError as e:
        logger.error(f"Database error during transfer: {e}")
        return Response({"detail": "Transfer failed due to database error"}, status=500)
    except Exception as e:
        logger.error(f"Unexpected error during transfer: {e}")
        return Response({"detail": "An unexpected error occurred"}, status=500)


@router.get(
    "/transactions",
    response=List[TransactionHistorySchema],
    url_name="wallet-transactions",
    auth=JWTAPIKeyAuth(dual_auth=True, permissions=["read"]),
)
@paginate
def get_wallet_history(request):
    user = request.auth
    transactions = Transaction.objects.filter(user=user).order_by("-created_at")
    all_tx_list = []
    try:
        for tx in transactions:
            tx_data = {
                "id": tx.id,
                "type": tx.type,
                "amount": tx.amount,
                "status": tx.status,
                "reference": tx.reference,
                "created_at": tx.created_at,
            }
            all_tx_list.append(tx_data)
        return Response({"transactions": all_tx_list}, status=200)
    except DatabaseError as e:
        logger.error(f"Database error getting transactions: {e}")
        return Response({"detail": "Transactions retrieval failed"}, status=500)
