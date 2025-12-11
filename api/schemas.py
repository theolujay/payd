from uuid import UUID
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ConfigDict
from ninja import ModelSchema
from api.models import APIKey, User

class UserSchema(ModelSchema):
    """User profile with wallet information"""

    wallet_number: Optional[int] = Field(None, description="User's unique wallet number")

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
        """Extract wallet number from user's wallet"""
        return (
            obj.wallet.wallet_number if hasattr(obj, "wallet") and obj.wallet else None
        )


class GoogleAuthURLResponse(BaseModel):
    """Google OAuth authorization URL"""

    auth_url: str = Field(..., description="Google OAuth authorization URL to open in browser")


class UserInfo(BaseModel):
    """Basic user information"""

    id: str = Field(..., description="User's unique identifier")
    email: str = Field(..., description="User's email address")
    name: str = Field(..., description="User's full name")
    picture: str | None = Field(None, description="URL to user's profile picture")


class TokenResponse(BaseModel):
    """JWT authentication tokens with user info"""

    access: str = Field(..., description="JWT access token for API authentication")
    refresh: str = Field(..., description="JWT refresh token to obtain new access tokens")
    user: UserInfo = Field(..., description="Authenticated user information")


class RefreshTokenRequest(BaseModel):
    """Request to refresh expired access token"""

    refresh: str = Field(..., description="Valid refresh token")


# Payment amount validation constants
MIN_AMOUNT = 5_000  # ₦50 in kobo
MAX_AMOUNT = 1_000_000_000  # ₦10,000,000 in kobo
JS_MAX_SAFE_INT = 9_007_199_254_740_991  # JavaScript's safe integer limit


class WalletDepositRequest(BaseModel):
    """Wallet deposit request with amount validation"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "amount": 10_000_000,
                },
                {
                    "amount": "10_000_000",
                }
            ]
        }
    )

    amount: int | str = Field(
        default=MIN_AMOUNT,
        description=(
            "Deposit amount in kobo (100 kobo = ₦1). "
            "Minimum: ₦50 (5,000 kobo), Maximum: ₦10,000,000 (1,000,000,000 kobo). "
            "Use underscores for readability: 10_000_000 instead of 10000000"
        ),
        examples=[10_000_000, "10_000_000"],
    )

    @field_validator("amount", mode="before")
    @classmethod
    def normalize_amount(cls, v):
        """Convert string input with underscores to integer"""
        if isinstance(v, str):
            try:
                v = int(v.replace("_", ""))
            except ValueError:
                raise ValueError("Amount must be a valid number")
        return v

    @field_validator("amount")
    @classmethod
    def validate_business_rules(cls, v):
        """Validate amount is within acceptable business and technical limits"""
        if not isinstance(v, int):
            raise ValueError("Amount must be an integer")
        if v > JS_MAX_SAFE_INT:
            raise ValueError("Amount must be a safe number")
        if v < MIN_AMOUNT:
            raise ValueError(f"Amount too small. Minimum is ₦50 ({MIN_AMOUNT:,} kobo)")
        if v > MAX_AMOUNT:
            raise ValueError(f"Amount too large. Maximum is ₦10,000,000 ({MAX_AMOUNT:,} kobo)")
        return v


class WalletToWalletTransferRequest(BaseModel):
    """Wallet-to-wallet transfer request"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "wallet_number": 1234567890,
                    "amount": 5_000_000
                }
            ]
        }
    )

    wallet_number: int = Field(
        ..., 
        description="Recipient's 10-digit wallet number",
        examples=[1234567890]
    )
    amount: int = Field(
        ..., 
        description="Transfer amount in kobo (100 kobo = ₦1)",
        examples=[5_000_000],
        gt=0
    )


class TransactionHistorySchema(BaseModel):
    """Transaction record for history listing"""

    id: UUID = Field(..., description="Unique transaction identifier")
    type: str = Field(..., description="Transaction type (deposit, transfer_in, transfer_out)")
    amount: int = Field(..., description="Transaction amount in kobo")
    status: str = Field(..., description="Transaction status (pending, success, failed)")
    reference: Optional[str] = Field(None, description="Payment gateway reference (for deposits)")
    created_at: datetime = Field(..., description="Transaction creation timestamp")


class PaymentInitiateResponse(BaseModel):
    """Paystack payment initialization response"""

    reference: str = Field(..., description="Unique payment reference ID")
    authorization_url: str = Field(..., description="Paystack payment page URL - redirect user here")


class TransactionStatusResponse(BaseModel):
    """Transaction status details"""

    reference: str = Field(..., description="Transaction reference ID")
    status: str = Field(..., description="Current transaction status")
    amount: int = Field(..., description="Transaction amount in kobo")
    paid_at: datetime | None = Field(None, description="Payment completion timestamp")
    currency: str = Field(default="NGN", description="Currency code")


class CreateAPIKeysRequest(BaseModel):
    """API key creation request with validation"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "Read Deposit key",
                    "permissions": ["read", "deposit"],
                    "expiry": "1Y"
                }
            ]
        }
    )

    name: str = Field(
        ..., 
        description="Human-readable key name (max 30 characters)",
        max_length=30,
        examples=["Read Deposit key", "Transfer Key"]
    )
    permissions: List[str] = Field(
        ...,
        description="List of permissions. Available: 'read', 'deposit', 'transfer'",
        examples=[["read", "deposit"], ["read", "deposit", "transfer"]]
    )
    expiry: str = Field(
        ...,
        description="Key expiration period: '1H' (1 hour), '1D' (1 day), '1M' (30 days), '1Y' (1 year)",
        examples=["1M", "1Y"]
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        """Ensure name length is within limits"""
        if len(v) > 30:
            raise ValueError("Name cannot exceed 30 characters")
        return v

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v):
        """Validate permissions are from allowed set"""
        allowed = {"read", "deposit", "transfer"}

        if isinstance(v, (list, set)):
            invalid = set(v) - allowed
            if invalid:
                raise ValueError(f"Invalid permissions: {invalid}. Allowed: {allowed}")
        elif v not in allowed:
            raise ValueError(f"Allowed permissions: {', '.join(allowed)}")

        return v

    @field_validator("expiry")
    @classmethod
    def validate_expiry(cls, v):
        """Validate expiry format"""
        if v not in ["1H", "1D", "1M", "1Y"]:
            raise ValueError("Allowed expiry options: '1H', '1D', '1M', '1Y'")
        return v


class RolloverAPIKeyRequest(BaseModel):
    """API key rollover request for expired keys"""
    
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "expired_key_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                    "expiry": "1Y"
                }
            ]
        }
    )

    expired_key_id: UUID = Field(
        ..., 
        description="UUID of the expired API key to replace",
        examples=["3fa85f64-5717-4562-b3fc-2c963f66afa6"]
    )
    expiry: str = Field(
        ...,
        description="New expiration period: '1H', '1D', '1M', or '1Y'",
        examples=["1Y"]
    )

    @field_validator("expiry")
    @classmethod
    def validate_expiry(cls, v):
        """Validate expiry format"""
        if v not in ["1H", "1D", "1M", "1Y"]:
            raise ValueError("Allowed expiry options: '1H', '1D', '1M', '1Y'")
        return v


class KeysListSchema(ModelSchema):
    """API key listing with essential details"""

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