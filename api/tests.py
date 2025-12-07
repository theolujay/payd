import json
import hmac
import hashlib
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch, Mock

from django.utils import timezone
from django.test import TestCase
from django.db import IntegrityError
from django.urls import reverse
from paystack import APIError

from api.models import User, Transaction


class TestGoogleAuth(TestCase):
    def test_sign_in_redirect(self):
        """Test that the endpoint returns a 302 redirect"""
        login_url = reverse("payd_api:google-login")
        response = self.client.get(login_url)
        self.assertEqual(response.status_code, 302)

    def test_redirect_url_correct_params(self):
        """Test that the redirect URL is correct"""
        url = reverse("payd_api:google-login")
        response = self.client.get(url)

        redirect_url = response.url
        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)

        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "accounts.google.com")
        self.assertEqual(parsed.path, "/o/oauth2/v2/auth")

        self.assertIn("client_id", params)
        self.assertIn("redirect_uri", params)
        self.assertIn("scope", params)
        self.assertIn("response_type", params)

        self.assertEqual(params["response_type"][0], "code")

    @patch("api.endpoints.GoogleOAuthConfig.CLIENT_ID", None)
    def test_missing_client_id(self):
        """Test case when CLIENT_ID is missing"""
        login_url = reverse("payd_api:google-login")
        response = self.client.get(login_url)

        self.assertEqual(response.status_code, 500)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "OAuth not configured")

    @patch("api.endpoints.GoogleOAuthConfig.CLIENT_SECRET", None)
    def test_missing_client_secret(self):
        """Test case when CLIENT_SECRET is missing"""
        login_url = reverse("payd_api:google-login")
        response = self.client.get(login_url)

        self.assertEqual(response.status_code, 500)

    # CALLBACK TESTS
    def test_callback_missing_code(self):
        """Test callback fails when code parameter is missing"""
        callback_url = reverse("payd_api:google-callback")
        response = self.client.get(callback_url)

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "missing code")

    @patch("api.endpoints.requests.post")
    def test_callback_invalid_code(self, mock_post):
        """Test callback with invalid authorization code"""
        mock_post.return_value.status_code = 400
        mock_post.return_value.json.return_value = {"error": "invalid_grant"}

        callback_url = reverse("payd_api:google-callback")
        response = self.client.get(callback_url, {"code": "invalid_code"})

        self.assertEqual(response.status_code, 401)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "invalid code")

    @patch("api.endpoints.requests.get")
    @patch("api.endpoints.requests.post")
    def test_callback_success_new_user(self, mock_post, mock_get):
        """Test successful callback with new user creation"""
        # Mock token exchange
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "access_token": "ya29.mock_token",
            "expires_in": 3599,
            "token_type": "Bearer",
        }

        # Mock userinfo response
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "id": "108942348239847",
            "email": "test@gmail.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "picture": "https://example.com/photo.jpg",
        }

        callback_url = reverse("payd_api:google-callback")
        response = self.client.get(callback_url, {"code": "valid_code"})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("user_id", data)
        self.assertEqual(data["email"], "test@gmail.com")
        self.assertEqual(data["name"], "Test User")

        # Verify user was created
        user = User.objects.get(email="test@gmail.com")
        self.assertEqual(user.google_id, "108942348239847")
        self.assertEqual(user.first_name, "Test")
        self.assertEqual(user.last_name, "User")
        self.assertEqual(user.picture_url, "https://example.com/photo.jpg")

    @patch("api.endpoints.requests.get")
    @patch("api.endpoints.requests.post")
    def test_callback_success_existing_user(self, mock_post, mock_get):
        """Test successful callback with existing user update"""
        # Create existing user
        existing_user = User.objects.create_user(
            email="test@gmail.com",
            google_id="108942348239847",
            first_name="Old",
            last_name="Name",
        )

        # Mock token exchange
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {
            "access_token": "ya29.mock_token",
            "expires_in": 3599,
            "token_type": "Bearer",
        }

        # Mock userinfo response with updated info
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "id": "108942348239847",
            "email": "test@gmail.com",
            "name": "Updated User",
            "given_name": "Updated",
            "family_name": "User",
            "picture": "https://example.com/new-photo.jpg",
        }

        callback_url = reverse("payd_api:google-callback")
        response = self.client.get(callback_url, {"code": "valid_code"})

        self.assertEqual(response.status_code, 200)

        # Verify user was updated, not duplicated
        self.assertEqual(User.objects.count(), 1)
        user = User.objects.get(google_id="108942348239847")
        self.assertEqual(user.first_name, "Updated")
        self.assertEqual(user.last_name, "User")

    @patch("api.endpoints.requests.post")
    def test_callback_google_token_error(self, mock_post):
        """Test callback when Google token endpoint fails"""
        mock_post.side_effect = Exception("Connection error")

        callback_url = reverse("payd_api:google-callback")
        response = self.client.get(callback_url, {"code": "valid_code"})

        self.assertEqual(response.status_code, 500)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "provider error")


class TestTransactionModel(TestCase):
    def setUp(self):
        """Create a test user for foreign key relationships"""
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="Test",
            last_name="User",
        )

    def test_transaction_creation(self):
        """Test that a transaction can be created with all required fields"""
        transaction = Transaction.objects.create(
            reference="TEST_REF_001",
            user=self.user,
            amount=500000,  # 5000 NGN in Kobo
            currency="NGN",
            status=Transaction.Status.PENDING,
            authorization_url="https://checkout.paystack.com/test123",
        )

        self.assertEqual(transaction.reference, "TEST_REF_001")
        self.assertEqual(transaction.user, self.user)
        self.assertEqual(transaction.amount, 500000)
        self.assertEqual(transaction.currency, "NGN")
        self.assertEqual(transaction.status, Transaction.Status.PENDING)
        self.assertIsNotNone(transaction.id)
        self.assertIsNotNone(transaction.created_at)
        self.assertIsNotNone(transaction.updated_at)

    def test_transaction_reference_unique(self):
        """Test that reference field has unique constraint"""
        Transaction.objects.create(
            reference="UNIQUE_REF",
            amount=100000,
        )

        with self.assertRaises(IntegrityError):
            Transaction.objects.create(
                reference="UNIQUE_REF",
                amount=200000,
            )

    def test_transaction_user_nullable(self):
        """Test that user field can be null"""
        transaction = Transaction.objects.create(
            reference="NO_USER_REF",
            amount=100000,
            user=None,
        )

        self.assertIsNone(transaction.user)

    def test_transaction_status_choices(self):
        """Test that status field uses correct choices"""
        # Test pending
        t1 = Transaction.objects.create(
            reference="REF_PENDING",
            amount=100000,
            status=Transaction.Status.PENDING,
        )
        self.assertEqual(t1.status, "pending")

        # Test success
        t2 = Transaction.objects.create(
            reference="REF_SUCCESS",
            amount=100000,
            status=Transaction.Status.SUCCESS,
        )
        self.assertEqual(t2.status, "success")

        # Test failed
        t3 = Transaction.objects.create(
            reference="REF_FAILED",
            amount=100000,
            status=Transaction.Status.FAILED,
        )
        self.assertEqual(t3.status, "failed")

    def test_transaction_default_status_pending(self):
        """Test that default status is pending"""
        transaction = Transaction.objects.create(
            reference="DEFAULT_STATUS",
            amount=100000,
        )

        self.assertEqual(transaction.status, Transaction.Status.PENDING)

    def test_transaction_default_currency_ngn(self):
        """Test that default currency is NGN"""
        transaction = Transaction.objects.create(
            reference="DEFAULT_CURRENCY",
            amount=100000,
        )

        self.assertEqual(transaction.currency, "NGN")

    def test_transaction_paid_at_nullable(self):
        """Test that paid_at field can be null"""
        transaction = Transaction.objects.create(
            reference="NO_PAID_AT",
            amount=100000,
        )

        self.assertIsNone(transaction.paid_at)

    def test_transaction_indexes_exist(self):
        """Test that appropriate indexes exist"""
        # This test verifies the indexes are defined in Meta
        indexes = Transaction._meta.indexes
        index_fields = [idx.fields for idx in indexes]

        self.assertIn(["reference"], index_fields)
        self.assertIn(["status"], index_fields)

    def test_transaction_ordering(self):
        """Test that transactions are ordered by created_at desc"""
        t1 = Transaction.objects.create(reference="REF_1", amount=100000)
        t2 = Transaction.objects.create(reference="REF_2", amount=200000)
        t3 = Transaction.objects.create(reference="REF_3", amount=300000)

        transactions = list(Transaction.objects.all())
        self.assertEqual(transactions[0], t3)
        self.assertEqual(transactions[1], t2)
        self.assertEqual(transactions[2], t1)

    def test_transaction_str_representation(self):
        """Test string representation of transaction"""
        transaction = Transaction.objects.create(
            reference="STR_TEST",
            amount=100000,
            status=Transaction.Status.SUCCESS,
        )

        self.assertEqual(str(transaction), "Transaction STR_TEST - success")


class TestPaystackPaymentInitiation(TestCase):
    def setUp(self):
        """Create a test user"""
        self.user = User.objects.create_user(
            email="test@example.com",
            first_name="Test",
            last_name="User",
        )

    def test_initiate_payment_success_with_email(self):
        """Test successful payment initiation with email"""
        with patch(
            "api.endpoints.paystack_client.transactions.initialize"
        ) as mock_init:
            mock_init.return_value = (
                {
                    "authorization_url": "https://checkout.paystack.com/test123",
                    "access_code": "test_access",
                    "reference": "TEST_REF_12345",
                },
                {},
            )

            url = reverse("payd_api:paystack-initiate")
            response = self.client.post(
                url,
                data={"amount": 500000, "email": "test@example.com"},
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 201)
            data = response.json()
            self.assertIn("reference", data)
            self.assertIn("authorization_url", data)
            self.assertEqual(data["reference"], "TEST_REF_12345")

            # Verify transaction was created
            transaction = Transaction.objects.get(reference="TEST_REF_12345")
            self.assertEqual(transaction.amount, 500000)
            self.assertEqual(transaction.status, Transaction.Status.PENDING)
            self.assertIsNone(transaction.user)

    def test_initiate_payment_success_with_user_id(self):
        """Test successful payment initiation with user_id"""
        with patch(
            "api.endpoints.paystack_client.transactions.initialize"
        ) as mock_init:
            mock_init.return_value = (
                {
                    "authorization_url": "https://checkout.paystack.com/test123",
                    "access_code": "test_access",
                    "reference": "TEST_REF_12345",
                },
                {},
            )

            url = f'{reverse("payd_api:paystack-initiate")}?user_id={self.user.id}'
            response = self.client.post(
                url,
                data={"amount": 500000},
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 201)
            data = response.json()
            self.assertIn("reference", data)
            self.assertIn("authorization_url", data)
            self.assertEqual(data["reference"], "TEST_REF_12345")

            # Verify transaction was created and associated with user
            transaction = Transaction.objects.get(reference="TEST_REF_12345")
            self.assertEqual(transaction.amount, 500000)
            self.assertEqual(transaction.status, Transaction.Status.PENDING)
            self.assertEqual(transaction.user, self.user)

            # Verify paystack was called with the user's email
            mock_init.assert_called_once_with(
                amount=500000,
                email=self.user.email,
                currency="NGN",
            )

    def test_initiate_payment_with_user_id_and_email(self):
        """Test that user_id takes precedence over email"""
        with patch(
            "api.endpoints.paystack_client.transactions.initialize"
        ) as mock_init:
            mock_init.return_value = (
                {"authorization_url": "", "reference": "test_ref"},
                {},
            )
            url = f'{reverse("payd_api:paystack-initiate")}?user_id={self.user.id}'
            self.client.post(
                url,
                data={"amount": 500000, "email": "wrong@example.com"},
                content_type="application/json",
            )
            mock_init.assert_called_once_with(
                amount=500000, email=self.user.email, currency="NGN"
            )

    def test_initiate_payment_with_non_existent_user_id(self):
        """Test payment initiation with non-existent user_id"""
        url = f'{reverse("payd_api:paystack-initiate")}?user_id=non-existent-id'
        response = self.client.post(
            url,
            data={"amount": 500000},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)

    def test_initiate_payment_without_email_or_user_id(self):
        """Test payment initiation without email or user_id"""
        url = reverse("payd_api:paystack-initiate")
        response = self.client.post(
            url,
            data={"amount": 500000},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_initiate_payment_invalid_amount(self):
        """Test payment initiation with invalid amount"""
        url = reverse("payd_api:paystack-initiate")
        response = self.client.post(
            url,
            data={"amount": -1000},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 422)  # Pydantic validation error

    def test_initiate_payment_zero_amount(self):
        """Test payment initiation with zero amount"""
        url = reverse("payd_api:paystack-initiate")
        response = self.client.post(
            url,
            data={"amount": 0},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 422)

    def test_initiate_payment_paystack_error(self):
        """Test payment initiation when Paystack API fails"""
        with patch(
            "api.endpoints.paystack_client.transactions.initialize"
        ) as mock_init:
            mock_init.side_effect = APIError("Paystack error", 400)

            url = reverse("payd_api:paystack-initiate")
            response = self.client.post(
                url,
                data={"amount": 500000},
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 402)
            self.assertIn("error", response.json())
            self.assertEqual(response.json()["error"], "payment initiation failed")

    def test_initiate_payment_idempotency(self):
        """Test idempotency - duplicate payment returns existing transaction"""
        # Create existing transaction
        existing_tx = Transaction.objects.create(
            reference="EXISTING_REF",
            amount=500000,
            status=Transaction.Status.PENDING,
            authorization_url="https://checkout.paystack.com/existing",
        )

        with patch(
            "api.endpoints.paystack_client.transactions.initialize"
        ) as mock_init:
            url = reverse("payd_api:paystack-initiate")
            response = self.client.post(
                url,
                data={"amount": 500000},
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 201)
            data = response.json()
            self.assertEqual(data["reference"], "EXISTING_REF")

            # Verify Paystack was NOT called
            mock_init.assert_not_called()

            # Verify no duplicate was created
            self.assertEqual(Transaction.objects.count(), 1)

    def test_initiate_payment_service_unavailable(self):
        """Test payment initiation when Paystack service is unavailable"""
        with patch(
            "api.endpoints.paystack_client.transactions.initialize"
        ) as mock_init:
            mock_init.side_effect = Exception("Connection timeout")

            url = reverse("payd_api:paystack-initiate")
            response = self.client.post(
                url,
                data={"amount": 500000},
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 500)
            self.assertIn("error", response.json())


class TestPaystackWebhook(TestCase):
    def setUp(self):
        """Create test transaction"""
        self.transaction = Transaction.objects.create(
            reference="TEST_REF_WEBHOOK",
            amount=500000,
            status=Transaction.Status.PENDING,
            authorization_url="https://checkout.paystack.com/test",
        )

        self.webhook_url = reverse("payd_api:paystack-webhook")
        self.webhook_secret = "test_webhook_secret"

    def _generate_signature(self, payload: dict) -> str:
        """Helper to generate valid Paystack signature"""
        json_payload = json.dumps(payload)
        return hmac.new(
            self.webhook_secret.encode("utf-8"),
            json_payload.encode("utf-8"),
            hashlib.sha512,
        ).hexdigest()

    @patch("api.utils.settings.PAYSTACK_WEBHOOK_SECRET", "test_webhook_secret")
    def test_webhook_success(self):
        """Test successful webhook processing"""
        payload = {
            "event": "charge.success",
            "data": {
                "reference": "TEST_REF_WEBHOOK",
                "status": "success",
                "paid_at": "2024-12-06T10:00:00.000Z",
                "amount": 500000,
            },
        }

        signature = self._generate_signature(payload)

        response = self.client.post(
            self.webhook_url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_PAYSTACK_SIGNATURE=signature,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], True)

        # Verify transaction was updated
        self.transaction.refresh_from_db()
        self.assertEqual(self.transaction.status, Transaction.Status.SUCCESS)
        self.assertIsNotNone(self.transaction.paid_at)

    def test_webhook_missing_signature(self):
        """Test webhook without signature header"""
        payload = {
            "event": "charge.success",
            "data": {"reference": "TEST_REF_WEBHOOK", "status": "success"},
        }

        response = self.client.post(
            self.webhook_url,
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "invalid signature")

        # Verify transaction was NOT updated
        self.transaction.refresh_from_db()
        self.assertEqual(self.transaction.status, Transaction.Status.PENDING)

    @patch("api.utils.settings.PAYSTACK_WEBHOOK_SECRET", "test_webhook_secret")
    def test_webhook_invalid_signature(self):
        """Test webhook with invalid signature"""
        payload = {
            "event": "charge.success",
            "data": {"reference": "TEST_REF_WEBHOOK", "status": "success"},
        }

        response = self.client.post(
            self.webhook_url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_PAYSTACK_SIGNATURE="invalid_signature_123",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid signature")

        # Verify transaction was NOT updated
        self.transaction.refresh_from_db()
        self.assertEqual(self.transaction.status, Transaction.Status.PENDING)

    @patch("api.utils.settings.PAYSTACK_WEBHOOK_SECRET", "test_webhook_secret")
    def test_webhook_unknown_reference(self):
        """Test webhook with unknown transaction reference"""
        payload = {
            "event": "charge.success",
            "data": {
                "reference": "UNKNOWN_REF",
                "status": "success",
                "paid_at": "2024-12-06T10:00:00.000Z",
            },
        }

        signature = self._generate_signature(payload)

        response = self.client.post(
            self.webhook_url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_PAYSTACK_SIGNATURE=signature,
        )

        # Should still return 200 to acknowledge receipt
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], True)

    @patch("api.utils.settings.PAYSTACK_WEBHOOK_SECRET", "test_webhook_secret")
    @patch("api.endpoints.Transaction.objects.get")
    def test_webhook_database_error(self, mock_get):
        """Test webhook when database is unavailable"""
        mock_get.side_effect = Exception("Database connection failed")

        payload = {
            "event": "charge.success",
            "data": {
                "reference": "TEST_REF_WEBHOOK",
                "status": "success",
                "paid_at": "2024-12-06T10:00:00.000Z",
            },
        }

        signature = self._generate_signature(payload)

        response = self.client.post(
            self.webhook_url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_PAYSTACK_SIGNATURE=signature,
        )

        self.assertEqual(response.status_code, 500)
        self.assertIn("error", response.json())

    @patch("api.utils.settings.PAYSTACK_WEBHOOK_SECRET", "test_webhook_secret")
    def test_webhook_failed_transaction(self):
        """Test webhook for failed transaction"""
        payload = {
            "event": "charge.success",
            "data": {
                "reference": "TEST_REF_WEBHOOK",
                "status": "failed",
                "paid_at": None,
            },
        }

        signature = self._generate_signature(payload)

        response = self.client.post(
            self.webhook_url,
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_X_PAYSTACK_SIGNATURE=signature,
        )

        self.assertEqual(response.status_code, 200)

        # Verify transaction status updated to failed
        self.transaction.refresh_from_db()
        self.assertEqual(self.transaction.status, Transaction.Status.FAILED)
        self.assertIsNone(self.transaction.paid_at)


class TestTransactionStatus(TestCase):
    def setUp(self):
        """Create test transaction"""
        self.transaction = Transaction.objects.create(
            reference="TEST_STATUS_REF",
            amount=500000,
            status=Transaction.Status.PENDING,
            authorization_url="https://checkout.paystack.com/test",
        )

    def test_get_transaction_status_from_database(self):
        """Test getting transaction status from database"""
        url = reverse(
            "payd_api:transaction-status", kwargs={"reference": "TEST_STATUS_REF"}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["reference"], "TEST_STATUS_REF")
        self.assertEqual(data["status"], "pending")
        self.assertEqual(data["amount"], 500000)
        self.assertIsNone(data["paid_at"])

    def test_get_transaction_status_not_found(self):
        """Test getting status for non-existent transaction"""
        url = reverse(
            "payd_api:transaction-status", kwargs={"reference": "UNKNOWN_REF"}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 404)
        self.assertIn("error", response.json())
        self.assertEqual(response.json()["error"], "transaction not found")

    def test_get_transaction_status_invalid_reference(self):
        """Test getting status with invalid reference format"""
        url = reverse("payd_api:transaction-status", kwargs={"reference": "ABC"})
        response = self.client.get(url)

        self.assertEqual(response.status_code, 400)
        self.assertIn("error", response.json())

    @patch("api.endpoints.paystack_client.transactions.verify")
    def test_get_transaction_status_with_refresh(self, mock_verify):
        """Test getting transaction status with Paystack refresh"""
        mock_verify.return_value = (
            {
                "reference": "TEST_STATUS_REF",
                "status": "success",
                "amount": 500000,
                "paid_at": "2024-12-06T10:00:00.000Z",
            },
            {},
        )

        url = reverse(
            "payd_api:transaction-status", kwargs={"reference": "TEST_STATUS_REF"}
        )
        response = self.client.get(url, {"refresh": "true"})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")

        # Verify Paystack was called
        mock_verify.assert_called_once_with(reference="TEST_STATUS_REF")

        # Verify database was updated
        self.transaction.refresh_from_db()
        self.assertEqual(self.transaction.status, Transaction.Status.SUCCESS)
        self.assertIsNotNone(self.transaction.paid_at)

    @patch("api.endpoints.paystack_client.transactions.verify")
    def test_get_transaction_status_refresh_failed_status(self, mock_verify):
        """Test refresh with failed transaction status"""
        mock_verify.return_value = (
            {
                "reference": "TEST_STATUS_REF",
                "status": "failed",
                "amount": 500000,
                "paid_at": None,
            },
            {},
        )

        url = reverse(
            "payd_api:transaction-status", kwargs={"reference": "TEST_STATUS_REF"}
        )
        response = self.client.get(url, {"refresh": "true"})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "failed")

        # Verify database was updated
        self.transaction.refresh_from_db()
        self.assertEqual(self.transaction.status, Transaction.Status.FAILED)

    @patch("api.endpoints.paystack_client.transactions.verify")
    def test_get_transaction_status_refresh_paystack_error(self, mock_verify):
        """Test refresh when Paystack API returns error"""
        mock_verify.side_effect = APIError("Paystack error", 400)

        url = reverse(
            "payd_api:transaction-status", kwargs={"reference": "TEST_STATUS_REF"}
        )
        response = self.client.get(url, {"refresh": "true"})

        # Should still return cached status
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "pending")

        # Verify database was NOT updated
        self.transaction.refresh_from_db()
        self.assertEqual(self.transaction.status, Transaction.Status.PENDING)

    @patch("api.endpoints.paystack_client.transactions.verify")
    def test_get_transaction_status_refresh_connection_error(self, mock_verify):
        """Test refresh when connection to Paystack fails"""
        mock_verify.side_effect = Exception("Connection timeout")

        url = reverse(
            "payd_api:transaction-status", kwargs={"reference": "TEST_STATUS_REF"}
        )
        response = self.client.get(url, {"refresh": "true"})

        # Should still return cached status
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "pending")

    def test_get_transaction_status_successful_transaction(self):
        """Test getting status for successful transaction"""
        # Update transaction to success
        self.transaction.status = Transaction.Status.SUCCESS
        self.transaction.paid_at = timezone.now()
        self.transaction.save()

        url = reverse(
            "payd_api:transaction-status", kwargs={"reference": "TEST_STATUS_REF"}
        )
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertIsNotNone(data["paid_at"])
