
from pydantic import BaseModel, Field, field_validator


class PaymentInitiateRequest(BaseModel):
    """Schema for payment initiation request"""

    amount: int = Field(..., gt=0, description="Amount in Kobo (smallest currency unit)")
    email: str | None = Field(None, description="Customer email (optional)")
    
    @field_validator("amount")
    @classmethod
    def validate_amount(cls, v):
        if v <= 0:
            raise ValueError("Amount must be greater than 0")
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