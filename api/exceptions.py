import logging
from ninja.errors import HttpError
from django.http import JsonResponse

logger = logging.getLogger(__name__)


class BaseAPIException(HttpError):
    """Base class for API exceptions"""

    def __init__(self, detail, status_code):
        super().__init__(status_code, detail)


class InvalidRequestException(BaseAPIException):
    """Exception for invalid requests"""

    def __init__(self, detail="Invalid request"):
        super().__init__(detail, status_code=400)


class NotFoundException(BaseAPIException):
    """Exception for not found errors"""

    def __init__(self, detail="Not found"):
        super().__init__(detail, status_code=404)


class IntegrationException(BaseAPIException):
    """Exception for integration errors"""

    def __init__(self, detail="An integration error occurred", status_code=500):
        super().__init__(detail, status_code=status_code)


def api_exception_handler(request, exc):
    """
    Handles exceptions for the API.
    """
    if isinstance(exc, BaseAPIException):
        logger.warning(f"API Exception: {exc.message} (Status Code: {exc.status_code})")
        return JsonResponse({"detail": exc.detail}, status=exc.status_code)

    logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
    return JsonResponse({"detail": "An unexpected error occurred"}, status=500)
