# api/tests.py
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch, Mock
from django.test import TestCase
from django.urls import reverse
from api.models import User


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