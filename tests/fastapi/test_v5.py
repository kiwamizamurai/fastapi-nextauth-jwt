import pytest
from fastapi.testclient import TestClient

from fastapi_nextauth_jwt.exceptions import MissingTokenError, InvalidTokenError, TokenExpiredException
from v5 import app

client = TestClient(app)

cookies = {
    "authjs.session-token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpKJKVb_jjf_Ld-zWA",
}

cookies_w_csrf = {
    "authjs.session-token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpKJKVb_jjf_Ld-zWA",
    "authjs.csrf-token": "53e18023db04541f0ffbe3c5f7683d2388806401eb46020f74889fa723a2623b%7C0a44296fabc59e85e37195731d6f132c78bc7884d33594ded089706f215c3647"
}

cookies_invalid = {
    "authjs.session-token": "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpFJKVb_jjf_Ld-zWA",
}

expected_jwt = {
  'name': 'asdf',
  'email': 'test@test.nl',
  'sub': '1',
  'iat': 1714146974,
  'exp': 1716738974,
  'jti': '9e8f6368-9236-458d-ba23-2bb95fdbfdbd'
}


@pytest.fixture(autouse=True)
def patch_current_time(monkeypatch):
    # Monkeypatch the current time so tests don't depend on it
    monkeypatch.setattr("fastapi_nextauth_jwt.operations.check_expiry.__defaults__", (1714146975,))


def test_no_csrf():
    client.cookies = cookies
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == expected_jwt


def test_csrf():
    client.cookies = cookies_w_csrf
    response = client.post("/csrf",
                           headers={
                               "X-XSRF-Token": "53e18023db04541f0ffbe3c5f7683d2388806401eb46020f74889fa723a2623b"
                           })

    assert response.status_code == 200
    assert response.json() == expected_jwt


def test_csrf_missing_token():
    with pytest.raises(MissingTokenError) as exc_info:
        client.cookies = cookies
        client.post("/csrf")
        assert exc_info.value.message == "Missing CSRF token: next-auth.csrf-token"


def test_csrf_missing_header():
    with pytest.raises(MissingTokenError) as exc_info:
        client.cookies = cookies_w_csrf
        client.post("/csrf")
        assert exc_info.value.message == "Missing CSRF header: X-XSRF-Token"


def test_csrf_no_csrf_method():
    client.cookies = cookies
    response = client.get("/csrf")

    assert response.status_code == 200
    assert response.json() == expected_jwt


def test_invalid_jwt():
    with pytest.raises(InvalidTokenError) as exc_info:
        client.cookies = cookies_invalid
        client.get("/")
        assert exc_info.value.message == "Invalid JWT format"


def test_expiry(monkeypatch):
    # In this case, we patch the current time to be after the token expiry time
    monkeypatch.setattr("fastapi_nextauth_jwt.operations.check_expiry.__defaults__", (1716738975,))

    with pytest.raises(TokenExpiredException) as exc_info:
        client.cookies = cookies
        client.get("/")
        assert exc_info.value.message == "Token Expired"

def test_verify_token():
    from v5 import JWT
    # Valid token
    token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpKJKVb_jjf_Ld-zWA"
    # Call verify_token method
    result = JWT.verify_token(token)
    # Expected result
    assert result == expected_jwt

def test_verify_token_invalid():
    from v5 import JWT
    # Invalid token
    invalid_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpFJKVb_jjf_Ld-zWA"
    # Verify that InvalidTokenError is raised when passing an invalid token
    with pytest.raises(InvalidTokenError) as exc_info:
        JWT.verify_token(invalid_token)
    assert exc_info.value.message == "Invalid JWT format"

def test_verify_token_expired(monkeypatch):
    from v5 import JWT
    from fastapi_nextauth_jwt.exceptions import TokenExpiredException
    # Set the time to an expired time
    # This is the same method used in other tests that works
    monkeypatch.setattr("fastapi_nextauth_jwt.operations.check_expiry.__defaults__", (1716738975,))
    # Valid token
    token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpKJKVb_jjf_Ld-zWA"
    # Verify that TokenExpiredException is raised when validating an expired token
    with pytest.raises(TokenExpiredException) as exc_info:
        JWT.verify_token(token)
    assert exc_info.value.message == "Token Expired"

def test_verify_token_with_csrf():
    from v5 import JWTwCSRF
    # Even with CSRF enabled instance, the verify_token method does not perform CSRF checks
    token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwia2lkIjoidDBOWWk4TExkYWVjNlctdlcwN3BRekdUR2dwSmgtaTBLRXlKcHFGcjRqSEkySkRtdDJNTnpqQ0Uwcjc0bDBFT240NmZOMUdMcEpsa09QY0NYZ2JNR3cifQ..VKK_QKVTc0-UxFoOD6ZxZg.pHmOvrG1kCq4IApuJD6lCplq5TBjhxGf_rd43h43kXddPGDwjSEUeRYbcSO-sSfXl8DnXw9Q9e1zJPMlxl1maZRaBV2kAla8kBebL19DPgEDHNVTmW_ujgidlSHk3bbNhOO1U1fXNdvUbQqHOAScjxv60CPJpVd-9CaL6Zw_Teg.S2KOuWV72JtSZca8VhOhQvSFofpKJKVb_jjf_Ld-zWA"
    # Call verify_token method
    result = JWTwCSRF.verify_token(token)
    # Expected result
    assert result == expected_jwt

def test_verify_token_missing_exp(monkeypatch):
    from v5 import JWT
    import json
    from jose import jwe
    from fastapi_nextauth_jwt.exceptions import InvalidTokenError
    # Replace jwe.decrypt with a mock function
    def mock_decrypt(token, key):
        # Return a JSON string with a fake token data that intentionally lacks an exp field
        return json.dumps({
            'name': 'asdf',
            'email': 'test@test.nl',
            'sub': '1',
            'iat': 1714146974,
            'jti': '9e8f6368-9236-458d-ba23-2bb95fdbfdbd'
            # exp field is intentionally missing
        }).encode()
    monkeypatch.setattr(jwe, "decrypt", mock_decrypt)
    # Any token string
    token = "dummy_token"
    # Verify that InvalidTokenError is raised when validating a token without an exp field
    with pytest.raises(InvalidTokenError) as exc_info:
        JWT.verify_token(token)
    assert exc_info.value.message == "Invalid JWT format, missing exp"