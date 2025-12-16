import logging
from datetime import datetime

from django.conf import settings
from django.utils import timezone
from celery import shared_task
from paystack import PaystackClient, APIError
from django.db import transaction, DatabaseError

from api.models import Transaction, Wallet, APIKey

logger = logging.getLogger(__name__)

paystack_client = PaystackClient(secret_key=settings.PAYSTACK_SECRET_KEY)

@shared_task(bind=True, retry_backoff=60, max_retries=5)
def verify_pending_paystack_transactions(self):
    """
    Celery task to verify pending Paystack transactions hourly.
    """
    logger.info("Starting verification of pending Paystack transactions...")

    pending_transactions = Transaction.objects.filter(
        status=Transaction.Status.PENDING,
        type=Transaction.Type.DEPOSIT
    )

    if not pending_transactions.exists():
        logger.info("No pending deposit transactions found to verify.")
        return

    for transaction_obj in pending_transactions:
        try:
            with transaction.atomic():
                logger.info(f"Verifying transaction reference: {transaction_obj.reference}")

                response, _ = paystack_client.transactions.verify(
                    reference=transaction_obj.reference
                )
                
                if response["status"] == "success":
                    amount = response["amount"]
                    
                    if amount == transaction_obj.amount:
                        transaction_obj.status = Transaction.Status.SUCCESS
                        transaction_obj.paid_at = response["paid_at"]
                        transaction_obj.updated_at = timezone.now()
                        
                        wallet = Wallet.objects.select_for_update().get(id=transaction_obj.wallet.id)
                        wallet.balance += transaction_obj.amount
                        wallet.updated_at = timezone.now()
                        
                        transaction_obj.save()
                        wallet.save()
                        
                        logger.info(
                            f"Transaction {transaction_obj.reference} "
                            "successfully verified and wallet updated."
                        )
                    else:
                        logger.warning(
                            f"Amount mismatch for transaction {transaction_obj.reference}. "
                            f"Expected {transaction_obj.amount}, got {amount} from Paystack."
                        )
                        transaction_obj.status = Transaction.Status.FAILED
                        transaction_obj.updated_at = timezone.now()
                        transaction_obj.save()
                else:
                    transaction_obj.status = Transaction.Status.FAILED
                    transaction_obj.updated_at = timezone.now()
                    transaction_obj.save()
                    logger.info(
                        f"Transaction {transaction_obj.reference} "
                        f"failed verification with status: {response['status']}"
                    )
                    
        except APIError as e:
            logger.warning(
                f"Paystack API error for transaction {transaction_obj.reference}: {e.message}"
            )

            self.retry(exc=e)
        except DatabaseError as e:
            logger.error(f"Database error for transaction {transaction_obj.reference}: {e}")
        except Exception as e:
            logger.error(
                f"An unexpected error occurred for transaction {transaction_obj.reference}: {e}"
            )

@shared_task(bind=True, retry_backoff=60, max_retries=3)
def revoke_expired_api_keys(self):
    """
    Celery task to revoke expired API keys.
    """
    logger.info("Starting task to revoke expired API keys...")

    now = timezone.now()
    expired_keys = APIKey.objects.filter(expires_at__lt=now, is_active=True)

    if not expired_keys.exists():
        logger.info("No expired API keys found to revoke.")
        return

    revoked_count = 0
    for key in expired_keys:
        try:
            key.is_active = False
            key.revoked_at = now
            key.save()
            revoked_count += 1
            logger.info(f"Revoked API key: {key.name} ({key.id})")
        except Exception as e:
            logger.error(f"Error revoking API key {key.id}: {e}")

    if revoked_count > 0:
        logger.info(f"Successfully revoked {revoked_count} expired API keys.")
    else:
        logger.info("No API keys were revoked in this run.")
