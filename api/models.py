import uuid
from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.contrib.auth.models import BaseUserManager, AbstractUser


class CustomUserManager(BaseUserManager):
    """Custom user manager for the user model"""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("the Email field must be set")
        email = self.normalize_email(email)

        if "username" not in extra_fields:
            extra_fields["username"] = email
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self.db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser with the given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """Custom user model"""

    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    email = models.EmailField(unique=True)
    is_email_verified = models.BooleanField(default=False)
    first_name = models.CharField(max_length=30, blank=False)
    last_name = models.CharField(max_length=30, blank=False)
    phone = models.CharField(blank=True)
    username = models.CharField(max_length=255, unique=True)
    google_id = models.CharField(max_length=255, unique=True, blank=True, null=True)
    picture_url = models.CharField(blank=True)
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def get_full_name(self):
        """Return the user's full name."""
        return f"{self.first_name} {self.last_name}".strip()


class Wallet(models.Model):
    """Wallet for users"""

    id = models.UUIDField(
        default=uuid.uuid4, unique=True, primary_key=True, editable=False
    )
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    wallet_number = models.CharField(max_length=20, unique=True)
    balance = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Transaction(models.Model):
    """Transaction model for storing wallet transaction information"""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        SUCCESS = "success", "Success"
        FAILED = "failed", "Failed"

    class Type(models.TextChoices):
        DEPOSIT = "deposit", "Deposit"
        TRANSFER_IN = "transfer_in", "Transfer In"
        TRANSFER_OUT = "transfer_out", "Transfer Out"

    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    wallet = models.ForeignKey("Wallet", on_delete=models.PROTECT, null=True)
    type = models.CharField(choices=Type.choices, db_index=True)
    amount = models.BigIntegerField(help_text="Amount in smallest currency unit (Kobo)")
    reference = models.CharField(max_length=255, unique=True, db_index=True)
    status = models.CharField(
        max_length=10, choices=Status.choices, default=Status.PENDING, db_index=True
    )
    currency = models.CharField(max_length=3, default="NGN")
    authorization_url = models.URLField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["wallet"]),
            models.Index(fields=["reference"]),
            models.Index(fields=["status"]),
            models.Index(fields=["type"]),
            models.Index(fields=["created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"Transaction {self.reference} - {self.type} - {self.status}"


class APIKey(models.Model):

    class Permission(models.TextChoices):
        READ_WALLET = "read_wallet", "Read Wallet"
        CREATE_TRANSACTION = "create_transaction", "Create Transaction"
        READ_TRANSACTION = "read_transaction", "Read Transaction"
        INITIATE_TRANSFER = "initiate_transfer", "Initiate Transfer"
        MANAGE_API_KEYS = "manage_api_keys", "Manage API Keys"

    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(
        max_length=30, blank=True, help_text="Friendly name for this API key"
    )
    key_hash = models.CharField(unique=True, max_length=128)
    permissions = ArrayField(
        models.CharField(max_length=20, choices=Permission.choices),
        default=list,
        help_text="List of permissions this API key grants",
    )
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "api_keys"
        indexes = [
            models.Index(fields=["user", "is_active"]),
        ]

    def __str__(self):
        return f"{self.name or 'Unnamed'} - {self.user.email}"
