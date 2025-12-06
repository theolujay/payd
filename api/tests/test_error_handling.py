import logging
from unittest.mock import patch, MagicMock

from django.test import TestCase, Client
from ninja.errors import HttpError

from api.exceptions import (
    BaseAPIException,
    InvalidRequestException,
    NotFoundException,
    IntegrationException,
    api_exception_handler,
)


class ExceptionHandlerTest(TestCase):
    def test_api_exception_handler_handles_base_api_exception(self):
        """
        Test that the api_exception_handler correctly handles BaseAPIException.
        """
        exc = BaseAPIException(detail="Test exception", status_code=400)
        response = api_exception_handler(None, exc)
        self.assertEqual(response, exc)

    def test_api_exception_handler_handles_unhandled_exceptions(self):
        """
        Test that the api_exception_handler correctly handles unhandled exceptions.
        """
        exc = Exception("An unexpected error")
        with self.assertLogs("api.exceptions", level="ERROR") as cm:
            response = api_exception_handler(None, exc)
            self.assertIsInstance(response, BaseAPIException)
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.message, "An unexpected error occurred.")
            self.assertIn("Unhandled Exception: An unexpected error", cm.output[0])


class CustomExceptionsTest(TestCase):
    def test_invalid_request_exception(self):
        """
        Test that InvalidRequestException has the correct status code and message.
        """
        exc = InvalidRequestException("Invalid data")
        self.assertEqual(exc.status_code, 400)
        self.assertEqual(exc.message, "Invalid data")

    def test_not_found_exception(self):
        """
        Test that NotFoundException has the correct status code and message.
        """
        exc = NotFoundException("Resource not found")
        self.assertEqual(exc.status_code, 404)
        self.assertEqual(exc.message, "Resource not found")

    def test_integration_exception(self):
        """
        Test that IntegrationException has the correct status code and message.
        """
        exc = IntegrationException("Third-party service error")
        self.assertEqual(exc.status_code, 500)
        self.assertEqual(exc.message, "Third-party service error")


class EndpointErrorHandlingTest(TestCase):
    def setUp(self):
        self.client = Client()

    @patch(
        "api.endpoints.get_google_token",
        side_effect=IntegrationException("Google auth failed"),
    )
    def test_google_callback_integration_error(self, mock_get_google_token):
        """
        Test that the google_callback endpoint returns a 500 error on integration failure.
        """
        response = self.client.get("/api/auth/google/callback?code=testcode")
        self.assertEqual(response.status_code, 500)
        self.assertJSONEqual(response.content, {"detail": "Google auth failed"})

    def test_google_callback_missing_code(self):
        """
        Test that the google_callback endpoint returns a 400 error if the code is missing.
        """
        response = self.client.get("/api/auth/google/callback")
        self.assertEqual(response.status_code, 400)
        self.assertJSONEqual(response.content, {"detail": "Missing authorization code"})

    @patch(
        "api.endpoints.paystack_client.transactions.initialize",
        side_effect=HttpError(500, "Paystack error"),
    )
    def test_initiate_payment_api_error(self, mock_initialize):
        """
        Test that the initiate_paystack_payment endpoint returns a 500 error on Paystack API failure.
        """
        response = self.client.post(
            "/api/payments/paystack/initiate",
            data={"amount": 1000, "email": "[email protected]"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 500)
        self.assertJSONEqual(
            response.content, {"detail": "An unexpected error occurred."}
        )

    def test_get_transaction_status_not_found(self):
        """
        Test that the get_transaction_status endpoint returns a 404 error for a non-existent transaction.
        """
        response = self.client.get("/api/payments/nonexistent/status")
        self.assertEqual(response.status_code, 404)
        self.assertJSONEqual(response.content, {"detail": "Transaction not found"})
