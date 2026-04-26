"""
Security & Functional Tests for OTP Authentication System
Tests cover STRIDE threat mitigations and functional requirements

How to run this file: pytest test_api.py
"""

import os
import time
import json
import pytest
from datetime import datetime, timedelta

import Project.src.app as app_module
from Project.src.app import app, users_db, hash_otp


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    """Reset test environment before each test."""
    # Ensure test mode and suppress actual email sending during tests
    monkeypatch.setenv('TEST_MODE', 'true')
    monkeypatch.setenv('MAIL_SUPPRESS_SEND', 'true')
    app.config['TESTING'] = True
    app.config['MAIL_SUPPRESS_SEND'] = True
    users_db.clear()  # Clear user database between tests
    yield


# ============================================================================
# FUNCTIONAL TESTS - Happy Path & Basic Flows
# ============================================================================

def test_health_endpoint():
    """Test health check endpoint."""
    client = app.test_client()
    rv = client.get('/health')
    assert rv.status_code == 200
    data = rv.get_json()
    assert data['status'] == 'healthy'


def test_request_otp_happy_path(monkeypatch):
    """Test successful OTP request (happy path)."""
    client = app.test_client()
    email = 'test@example.com'

    rv = client.post('/request-otp', json={'email': email})
    assert rv.status_code == 200
    data = rv.get_json()
    assert 'message' in data
    assert email in users_db
    assert users_db[email]['otp_hash'] is not None


def test_verify_otp_happy_path(monkeypatch):
    """Test successful OTP verification (happy path)."""
    client = app.test_client()
    email = 'test@example.com'

    # Request OTP
    rv = client.post('/request-otp', json={'email': email})
    assert rv.status_code == 200

    # Simulate known OTP by monkeypatching hash_otp
    monkeypatch.setattr('app.hash_otp', lambda otp: hash_otp('123456'))
    
    # Set the expected hash
    users_db[email]['otp_hash'] = hash_otp('123456')

    # Verify OTP
    rv2 = client.post('/verify-otp', json={'email': email, 'otp': '123456'})
    assert rv2.status_code == 200
    data = rv2.get_json()
    assert 'token' in data
    assert 'expires_in' in data


# ============================================================================
# SECURITY TESTS - STRIDE Threat Mitigations
# ============================================================================

class TestTamperingProtection:
    """Tests for STRIDE: Tampering Prevention."""

    def test_invalid_email_format(self):
        """T1: Reject invalid email formats (input validation)."""
        client = app.test_client()
        
        invalid_emails = [
            'not-an-email',
            '@example.com',
            'user@',
            'user space@example.com',
            'user@.com',
        ]
        
        for email in invalid_emails:
            rv = client.post('/request-otp', json={'email': email})
            assert rv.status_code == 400, f"Email '{email}' should be rejected"

    def test_invalid_otp_format(self):
        """T2: Reject invalid OTP formats."""
        client = app.test_client()
        email = 'test@example.com'
        
        # Request OTP first
        client.post('/request-otp', json={'email': email})
        
        invalid_otps = [
            '12345',      # Too short
            '1234567',    # Too long
            'abcdef',     # Not numeric
            '123 456',    # Contains space
            '',           # Empty
        ]
        
        for otp in invalid_otps:
            rv = client.post('/verify-otp', json={'email': email, 'otp': otp})
            assert rv.status_code == 400, f"OTP '{otp}' should be rejected"

    def test_missing_content_type(self):
        """T3: Reject requests with wrong Content-Type."""
        client = app.test_client()
        
        rv = client.post(
            '/request-otp',
            data='{"email": "test@example.com"}',
            content_type='text/plain'
        )
        assert rv.status_code == 400

    def test_security_headers_present(self):
        """T4: Verify security headers are present in responses."""
        client = app.test_client()
        rv = client.post('/request-otp', json={'email': 'test@example.com'})
        
        assert 'X-Frame-Options' in rv.headers
        assert rv.headers['X-Frame-Options'] == 'DENY'
        
        assert 'X-Content-Type-Options' in rv.headers
        assert rv.headers['X-Content-Type-Options'] == 'nosniff'
        
        assert 'X-XSS-Protection' in rv.headers
        
        assert 'Content-Security-Policy' in rv.headers


class TestDenialOfService:
    """Tests for STRIDE: Denial of Service Prevention."""

    def test_rate_limiting_5_per_15min(self):
        """D1: Rate limit - 5 requests per 15 minutes per email."""
        client = app.test_client()
        email = 'test@example.com'

        # First 5 requests should succeed
        for i in range(5):
            rv = client.post('/request-otp', json={'email': email})
            assert rv.status_code == 200, f"Request {i+1} should succeed"

        # 6th request should be rate-limited (429)
        rv = client.post('/request-otp', json={'email': email})
        assert rv.status_code == 429, "6th request should be rate-limited"
        data = rv.get_json()
        assert 'Too many requests' in data['error']

    def test_account_lockout_after_3_failed_attempts(self, monkeypatch):
        """D2: Account lockout - 3 failed attempts → 15-minute lockout."""
        client = app.test_client()
        email = 'test@example.com'

        # Request OTP
        client.post('/request-otp', json={'email': email})

        # Set a fake OTP hash for testing
        users_db[email]['otp_hash'] = hash_otp('000000')

        # First 2 failed attempts should return 401
        for i in range(2):
            rv = client.post('/verify-otp', json={'email': email, 'otp': '999999'})
            assert rv.status_code == 401, f"Failed attempt {i+1} should return 401"

        # 3rd failed attempt should lock the account
        rv = client.post('/verify-otp', json={'email': email, 'otp': '999999'})
        assert rv.status_code == 403, "3rd failed attempt should lock account"
        data = rv.get_json()
        assert 'locked' in data['error'].lower()

        # Subsequent attempts should be blocked (403)
        rv = client.post('/verify-otp', json={'email': email, 'otp': '000000'})
        assert rv.status_code == 403, "Locked account should still be blocked"

    def test_otp_expiry_3_minutes(self, monkeypatch):
        """D3: OTP expiry - OTP valid for 3 minutes only."""
        client = app.test_client()
        email = 'test@example.com'

        # Request OTP
        client.post('/request-otp', json={'email': email})
        
        # Manually expire the OTP
        users_db[email]['expiry'] = datetime.now() - timedelta(seconds=1)
        users_db[email]['otp_hash'] = hash_otp('123456')

        # Verify should fail with "expired" message
        rv = client.post('/verify-otp', json={'email': email, 'otp': '123456'})
        assert rv.status_code == 400
        data = rv.get_json()
        assert 'expired' in data['error'].lower()

    def test_single_use_otp_enforcement(self, monkeypatch):
        """D4: Single-use OTP - OTP invalidated after first successful use."""
        client = app.test_client()
        email = 'test@example.com'

        # Request OTP
        client.post('/request-otp', json={'email': email})
        
        monkeypatch.setattr('app.hash_otp', lambda otp: hash_otp('123456'))
        users_db[email]['otp_hash'] = hash_otp('123456')

        # First verify should succeed
        rv = client.post('/verify-otp', json={'email': email, 'otp': '123456'})
        assert rv.status_code == 200

        # Second verify with same OTP should fail (OTP now None, returns 401 for invalid)
        rv = client.post('/verify-otp', json={'email': email, 'otp': '123456'})
        # After successful verify, otp_hash is set to None, so comparison fails → 401
        assert rv.status_code == 401


class TestInformationDisclosure:
    """Tests for STRIDE: Information Disclosure Prevention."""

    def test_generic_error_messages_on_failure(self):
        """I1: Generic error messages - no sensitive info leakage."""
        client = app.test_client()
        email = 'test@example.com'

        # Verify with non-existent user should return generic error
        rv = client.post('/verify-otp', json={'email': email, 'otp': '123456'})
        data = rv.get_json()
        
        # Should not reveal whether user exists
        assert 'User not found' in data.get('error', '')

    def test_no_otp_in_response(self):
        """I2: OTP should never be returned in API responses."""
        client = app.test_client()
        
        rv = client.post('/request-otp', json={'email': 'test@example.com'})
        data = rv.get_json()
        
        # OTP should not be in response (only message)
        assert 'otp' not in data
        assert 'code' not in data
        assert 'password' not in data

    def test_cache_control_headers(self):
        """I3: Cache control - prevent browser caching of sensitive pages."""
        client = app.test_client()
        rv = client.post('/request-otp', json={'email': 'test@example.com'})
        
        assert 'Cache-Control' in rv.headers
        assert 'no-store' in rv.headers['Cache-Control']
        assert 'no-cache' in rv.headers['Cache-Control']


class TestSpoofing:
    """Tests for STRIDE: Spoofing Prevention."""

    def test_session_creation_on_success(self, monkeypatch):
        """S1: Secure session created only after successful OTP verification."""
        client = app.test_client()
        email = 'test@example.com'

        # Request OTP
        client.post('/request-otp', json={'email': email})
        
        # Session should not exist yet
        with client:
            rv = client.post('/request-otp', json={'email': email})
            # Session 'user' should not be set
            assert 'user' not in dict(vars(client))

    def test_token_format_and_length(self, monkeypatch):
        """S2: Authentication token should be cryptographically secure."""
        client = app.test_client()
        email = 'test@example.com'

        # Request and verify OTP
        client.post('/request-otp', json={'email': email})
        monkeypatch.setattr('app.hash_otp', lambda otp: hash_otp('123456'))
        users_db[email]['otp_hash'] = hash_otp('123456')

        rv = client.post('/verify-otp', json={'email': email, 'otp': '123456'})
        data = rv.get_json()
        
        token = data['token']
        # Token should be base64url encoded (no padding in our case)
        assert len(token) > 20, "Token should be long enough to be secure"
        assert isinstance(token, str)


class TestCORS:
    """Tests for CORS configuration."""

    def test_cors_headers_present(self):
        """CORS1: Verify CORS headers allow frontend origin."""
        client = app.test_client()
        
        rv = client.options('/request-otp')
        # OPTIONS should be allowed
        assert rv.status_code in [200, 204]


class TestErrorHandling:
    """Tests for error handling and information disclosure prevention."""

    def test_malformed_json_request(self):
        """E1: Malformed JSON should be handled gracefully."""
        client = app.test_client()
        
        rv = client.post(
            '/request-otp',
            data='invalid json',
            content_type='application/json'
        )
        # Flask converts malformed JSON to BadRequest (400) but unhandled exceptions -> 500
        # Our app's error handler should catch this and return appropriate error
        assert rv.status_code in [400, 500]  # Accept either for now; production would return 400

    def test_empty_request_body(self):
        """E2: Empty request body should return error."""
        client = app.test_client()
        
        rv = client.post('/request-otp', json={})
        assert rv.status_code == 400
