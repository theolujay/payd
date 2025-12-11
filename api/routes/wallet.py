"""
Wallet-related endpoints
"""

import logging
from typing import List

from django.conf import settings
from django.db import DatabaseError, transaction
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from ninja import Router, Query, Path
from ninja.responses import Response
from ninja.pagination import paginate
from paystack import PaystackClient, APIError

from api.utils import dual_auth, API_KEY_HEADER_SPEC
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
    auth=dual_auth(permissions=["deposit"]),
    summary="Initiate Wallet Deposit",
    description="""
    Initiate a Paystack payment to deposit funds into your wallet.
    
    Process:
    1. Send deposit amount in kobo (100 kobo = ₦1)
    2. Receive payment reference and authorization URL
    3. Redirect user to authorization URL to complete payment
    4. Paystack processes payment and sends webhook notification
    5. Wallet is credited automatically upon successful payment
    
    Amount format:
    - Amount must be in kobo (smallest currency unit)
    - Minimum: ₦50 (5,000 kobo)
    - Maximum: ₦10,000,000 (1,000,000,000 kobo)
    - You can use underscores for readability: 10_000_000 instead of 10000000
    
    Duplicate prevention: If a pending transaction with the same amount exists, returns the existing transaction details.
    
    Authentication: Requires JWT token OR API key with deposit permission.
    - JWT: Authorization: Bearer <token>
    - API Key: X-API-Key: <your_api_key>
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
def wallet_deposit_with_paystack(request, payload: WalletDepositRequest):
    """Initialize Paystack payment for wallet deposit and return authorization URL."""
    user = request.auth

    try:
        user_wallet = Wallet.objects.get(user=user)
        
        # Check for existing pending transaction to prevent duplicates
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
    except APIError as e:
        logger.error(f"Paystack API error: {e.message}")
        return Response({"detail": "Payment initiation failed"}, status=402)
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
    except DatabaseError as e:
        logger.error(f"Database error creating transaction: {str(e)}")
        return Response({"detail": "Failed to create transaction"}, status=500)


@router.get(
    "/transaction/{reference}/status",
    response=dict,
    url_name="transaction-status",
    auth=dual_auth(permissions=["read"]),
    summary="Get Transaction Status",
    description="""
    Retrieve the current status of a transaction by its reference ID.
    
    Query parameter:
    - refresh=false (default): Returns cached status from database
    - refresh=true: Fetches real-time status from Paystack
    
    Use cases:
    - Check if a payment has been completed
    - Verify transaction amount and status
    - Monitor pending transactions
    
    Transaction statuses:
    - pending: Payment initiated but not completed
    - success: Payment completed successfully
    - failed: Payment failed or was declined
    
    Authentication: Requires JWT token OR API key with read permission.
    - JWT: Authorization: Bearer <token>
    - API Key: X-API-Key: <your_api_key>
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
def get_transaction_status(
    request,
    reference: str = Path(..., description="Transaction reference ID (min 5 characters)"),
    refresh: bool = Query(False, description="Fetch live status from Paystack instead of cached"),
):
    """Get transaction status from database or fetch live status from Paystack."""
    if not reference or len(reference) < 5:
        return Response({"detail": "Invalid transaction reference format"}, status=400)

    try:
        transaction = Transaction.objects.get(reference=reference)
    except Transaction.DoesNotExist:
        return Response({"detail": "Transaction not found"}, status=404)

    user = request.auth
    if transaction.wallet and transaction.wallet.user.id != user.id:
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
    auth=dual_auth(permissions=["read"]),
    summary="Get Wallet Balance",
    description="""
    Retrieve your current wallet balance in kobo.
    
    Response: Returns balance in kobo (100 kobo = ₦1)
    
    Example: A balance of 5000000 kobo = ₦50,000
    
    Authentication: Requires JWT token OR API key with read permission.
    - JWT: Authorization: Bearer <token>
    - API Key: X-API-Key: <your_api_key>
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
def get_wallet_balance(request):
    """Get authenticated user's current wallet balance."""
    user = request.auth
    try:
        logger.info(f"Wallet balance request by usr: {user.email}")
        user_wallet = Wallet.objects.get(user=user)
        return Response({"balance": user_wallet.balance}, status=200)
    except Wallet.DoesNotExist:
        logger.warning(f"Wallet not found for user: {user.email}")
        return Response({"detail": "Wallet does not exist"}, status=404)


@router.post(
    "/transfer",
    response=dict,
    url_name="wallet-transfer",
    auth=dual_auth(permissions=["transfer"]),
    summary="Transfer Funds",
    description="""
    Transfer funds from your wallet to another user's wallet instantly.
    
    Requirements:
    - Recipient's 10-digit wallet number
    - Amount in kobo (must be > 0)
    - Sufficient balance in your wallet
    
    Restrictions:
    - Cannot transfer to your own wallet
    - Must have sufficient balance
    
    Transaction linking: Both sender and recipient transactions are linked via metadata for audit trails.
    
    Authentication: Requires JWT token OR API key with transfer permission.
    - JWT: Authorization: Bearer <token>
    - API Key: X-API-Key: <your_api_key>
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
def wallet_to_wallet_transfer(request, payload: WalletToWalletTransferRequest):
    """Transfer funds between wallets atomically with balance verification."""
    user = request.auth
    amount = payload.amount
    recipient_wallet_number = payload.wallet_number

    if amount <= 0:
        return Response({"detail": "Amount must be greater than 0"}, status=400)

    try:
        with transaction.atomic():
            # Lock rows to prevent race conditions
            user_wallet = Wallet.objects.select_for_update().get(user=user)

            if str(user_wallet.wallet_number) == str(recipient_wallet_number):
                return Response(
                    {"detail": "Cannot transfer to your own wallet"}, status=400
                )
            
            try:
                recipient_wallet = Wallet.objects.select_for_update().get(
                    wallet_number=recipient_wallet_number
                )
            except ObjectDoesNotExist:
                return Response({"detail": "Recipient wallet not found"}, status=404)

            if user_wallet.balance < amount:
                return Response({"detail": "Insufficient balance"}, status=400)

            # Create linked transaction records
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

            # Link transactions bidirectionally
            transfer_out.metadata = {"transfer_to_id": str(transfer_in.id)}
            transfer_in.metadata = {"transfer_from_id": str(transfer_out.id)}
            transfer_out.save()
            transfer_in.save()

            # Update balances
            user_wallet.balance -= amount
            recipient_wallet.balance += amount
            user_wallet.updated_at = timezone.now()
            recipient_wallet.updated_at = timezone.now()
            user_wallet.save()
            recipient_wallet.save()

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
    auth=dual_auth(permissions=["read"]),
    summary="Get Transaction History",
    description="""
    Retrieve your complete transaction history with pagination support.
    
    Returns: List of all transactions sorted by newest first, including:
    - Deposits (via Paystack)
    - Transfers sent (transfer_out)
    - Transfers received (transfer_in)
    
    Pagination: Use query parameters to control pagination:
    - limit: Number of transactions per page (default: 100)
    - offset: Number of transactions to skip
    
    Example: ?limit=20&offset=0 returns first 20 transactions
    
    Sorting: Transactions are always sorted by creation date (newest first)
    
    Authentication: Requires JWT token OR API key with read permission.
    - JWT: Authorization: Bearer <token>
    - API Key: X-API-Key: <your_api_key>
    """,
    openapi_extra=API_KEY_HEADER_SPEC,
)
@paginate
def get_wallet_history(request):
    """List all wallet transactions with pagination, newest first."""
    user = request.auth
    transactions = Transaction.objects.filter(wallet=user.wallet).order_by(
        "-created_at"
    )

    return [
        TransactionHistorySchema(
            id=t.id,
            type=t.type,
            amount=t.amount,
            status=t.status,
            reference=t.reference,
            created_at=t.created_at,
        )
        for t in transactions
    ]