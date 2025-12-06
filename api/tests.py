
from urllib.parse import urlparse, parse_qs
from unittest.mock import patch
from django.test import TestCase
from django.urls import reverse



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

    @patch('api.endpoints.GoogleOAuthConfig.CLIENT_SECRET', None)
    def test_missing_client_secret(self):
        """Test case when CLIENT_SECRET is missing"""
        login_url = reverse("payd_api:google-login")
        response = self.client.get(login_url)
        
        self.assertEqual(response.status_code, 500)
        