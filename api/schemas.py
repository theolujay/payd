from uuid import UUID
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
from ninja import ModelSchema
from api.models import APIKey, User


class UserSchema(ModelSchema):
    """Schema for user model"""
    wallet_number: Optional[int] = None
    class Meta:
        model = User
        fields = [
            "id",
            "email", 
            "first_name",
            "last_name",
            "phone",
            "picture_url",
        ]
        
    @staticmethod
    def resolve_wallet_number(obj):
        """Get wallet number from related wallet"""
        return obj.wallet.wallet_number if hasattr(obj, 'wallet') and obj.wallet else None

class GoogleAuthURLResponse(BaseModel):
    """Response with Google OAuth URL"""

    auth_url: str


class UserInfo(BaseModel):
    """User information"""

    id: str
    email: str
    name: str
    picture: str | None = None


class TokenResponse(BaseModel):
    """JWT token response"""

    access: str
    refresh: str
    user: UserInfo


class RefreshTokenRequest(BaseModel):
    """Request to refresh access token"""

    refresh: str = Field(..., description="Refresh token")


from pydantic import BaseModel, Field, field_validator

MIN_AMOUNT = 5_000            # ₦50 in kobo
MAX_AMOUNT = 10_000_000_00    # ₦10,000,000 in kobo
JS_MAX_SAFE_INT = 9_007_199_254_740_991  # JavaScript's safe integer limit

class WalletDepositRequest(BaseModel):
    """Schema for wallet deposit request sent to Paystack."""

    amount: int = Field(
        default=MIN_AMOUNT,
        ge=MIN_AMOUNT,
        le=MAX_AMOUNT,
        description=(
            "Deposit amount in kobo. Must be between ₦50 and ₦10,000,000. "
            "Only whole integers are allowed."
        ),
    )

    @field_validator("amount")
    @classmethod
    def validate_business_rules(cls, v):
        if not isinstance(v, int):
            raise ValueError("Amount must be an integer.")
        if v > JS_MAX_SAFE_INT:
            raise ValueError("Amount must be a safe number.")
        if v < MIN_AMOUNT:
            raise ValueError("Amount is too small to be processed online.")
        if v > MAX_AMOUNT:
            raise ValueError(
                "Amount exceeds the maximum allowed for online processing."
            )
        return v


class WalletToWalletTransferRequest(BaseModel):
    """Schema for wallet-to-wallet transfers"""

    wallet_number: int
    amount: int


class TransactionHistorySchema(BaseModel):
    """Schema for transaction history"""

    id: UUID
    type: str
    amount: int
    status: str
    reference: Optional[str]
    created_at: datetime


class PaymentInitiateResponse(BaseModel):
    """Schema for payment initiation response"""

    reference: str
    authorization_url: str


class TransactionStatusResponse(BaseModel):
    """Schema for transaction status response"""

    reference: str
    status: str
    amount: int
    paid_at: datetime | None = None
    currency: str = "NGN"


class CreateAPIKeysRequest(BaseModel):
    """Schema for creating API keys"""

    name: str
    permissions: List[str]
    expiry: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        if len(v) > 30:
            raise ValueError("Name cannot be more than 30 characters")
        return v

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v):
        allowed = {"read", "deposit", "transfer"}
        
        if isinstance(v, (list, set)):
            invalid = set(v) - allowed
            if invalid:
                raise ValueError(f"Invalid permissions: {invalid}. Allowed: {allowed}")
        elif v not in allowed:
            raise ValueError(f"Allowed permissions are: {', '.join(allowed)}")
        
        return v

    @field_validator("expiry")
    @classmethod
    def validate_expiry(cls, v):
        if v not in ["1H", "1D", "1M", "1Y"]:
            raise ValueError("Allowed expiry format: '1H', '1D', '1M', '1Y'")
        return v


class RolloverAPIKeyRequest(BaseModel):
    """Schema for API key rollover"""

    expired_key_id: UUID
    expiry: str

    @field_validator("expiry")
    @classmethod
    def validate_expiry(cls, v):
        if v not in ["1H", "1D", "1M", "1Y"]:
            raise ValueError("Allowed expiry format: '1H', '1D', '1M', '1Y'")
        return v


class KeysListSchema(ModelSchema):
    """Schema for listing active API keys"""

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "is_active",
            "permissions",
            "created_at",
            "expires_at",
        ]