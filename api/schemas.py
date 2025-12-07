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

class PaymentInitiateRequest(BaseModel):
    """Schema for payment initiation request"""

    amount: int = Field(5000, gt=0, description="Amount in Kobo (smallest currency unit)")

    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v):
        if v < 5000:
            raise ValueError("Amount must be at least 5000 (50 naira)")
        return v


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