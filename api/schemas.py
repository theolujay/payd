from uuid import UUID
from typing import List
from datetime import datetime
from pydantic import BaseModel, Field, field_validator

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

class WalletDepositRequest(BaseModel):
    """Schema for wallet deposit request"""

    amount: int = Field(5000, gt=0, description="Amount in Kobo (smallest currency unit)")

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v):
        if v < 5000:
            raise ValueError("Amount must be at least 5000 (50 naira)")
        return v

class WalletToWalletTransferRequest(BaseModel):
    """Schema for wallet-to-wallet transfers"""
    
    wallet_number: UUID
    amount: int
    
class TransactionHistorySchema(BaseModel):
    """Schema for transaction history"""

    id: UUID
    type: str
    amount: int
    status: str
    reference: str
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
            raise ValueError("Allowed permissions are: 'read', 'deposit', 'transfer")
        return v
    
    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v):
        if v not in ["read", "deposit", "transfer"]:
            raise ValueError("Allowed permissions are: 'read', 'deposit', 'transfer")
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

class KeysListSchema(BaseModel):
    """Schema for listing active API keys"""
    
    id: UUID
    name: str
    is_active: bool
    permissions: List[str]
    created_at: datetime
    expires_at: datetime