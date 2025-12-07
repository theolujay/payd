from pydantic import BaseModel, Field, field_validator


class PaymentInitiateRequest(BaseModel):
    """Schema for payment initiation request"""

    amount: int = Field(
        5000, gt=0, description="Amount in Kobo (smallest currency unit)"
    )
    email: str | None = Field(None, description="Customer email (optional)")

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


from datetime import datetime
from pydantic import BaseModel, Field


class TransactionStatusResponse(BaseModel):
    """Schema for transaction status response"""

    reference: str
    status: str
    amount: int
    paid_at: datetime | None = None
    currency: str = "NGN"
