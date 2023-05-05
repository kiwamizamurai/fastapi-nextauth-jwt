"""
A fastapi dependency used to decode jwt tokens generated by nextauth,
for use in nextjs/nextauth and fastapi mixed projects
"""

__version__ = "0.0.2"

from json import JSONDecodeError
import os
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from jose.exceptions import JWEError
from starlette.requests import Request
from jose import jwe
import json
import urllib.parse


class NextAuthJWTException(Exception):
    def __init__(self, *args: object):
        super().__init__(args)
        self.message = None
        self.status_code = None


class MissingTokenError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class InvalidTokenError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class CSRFMismatchError(NextAuthJWTException):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


_secure_cookie = os.getenv("NEXTAUTH_URL", "").startswith("https://")


class NextAuthJWTConfig:
    cookie_name = "__Secure-next-auth.session-token" if _secure_cookie else "next-auth.session-token"
    csrf_cookie_name = "__Host-next-auth.csrf-token" if _secure_cookie else "next-auth.csrf-token"
    csrf_header_name = "X-XSRF-Token"

    secret = bytes(str(os.environ.get("NEXTAUTH_SECRET")), "ascii")

    # https://github.com/nextauthjs/next-auth/blob/50fe115df6379fffe3f24408a1c8271284af660b/src/jwt/index.ts
    # We derive the key used for JWE encryption from the secret in the same way as NextAuth
    # Hardcoded in Nextauth
    info_bytes = b"NextAuth.js Generated Encryption Key"
    salt = b""
    key = HKDF(secret, 32, salt, SHA256, 1, context=info_bytes)

    csrf_prevention_enabled = False if os.environ.get("ENV") == "dev" else True
    csrf_methods = {'POST', 'PUT', 'PATCH', 'DELETE'}


class NextAuthJWT(NextAuthJWTConfig):
    """
    Get NextAuth jwt token and decrypt it from incoming request and verify CSRF token if needed.
    Only allows reading the JWT, generating is not supported at this point and is expected to be
    handled by NextAuth

    Heavily inspired by https://indominusbyte.github.io/fastapi-jwt-auth/

    :param req: incoming request
    """

    def __init__(self, req: Request = None):
        encrypted_token = self._extract_session_token(req)

        # Keep track of the request
        self._req = req

        # Check csrf token
        if self.csrf_prevention_enabled:
            self.check_csrf_token()

        # Decrypt token
        try:
            decrypted_token_string = jwe.decrypt(encrypted_token, self.key)
            self._token = json.loads(decrypted_token_string)
        except (JWEError, JSONDecodeError) as e:
            print(e)
            raise InvalidTokenError(status_code=401, message="Invalid JWT format")

    def _extract_session_token(self, req: Request):
        """
        Extracts the encrypted nextauth session token from the request.
        It may be in a single cookie, or chunked (with suffixes 0...n)
        :param req: The request to extract the token from
        :return: The encrypted nextauth session token
        """
        encrypted_token = ""

        # Do we have a session cookie with the expected name?
        if self.cookie_name in req.cookies:
            encrypted_token = req.cookies[self.cookie_name]

        # Or maybe a chunked session cookie?
        elif f"{self.cookie_name}.0" in req.cookies:
            counter = 0
            while f"{self.cookie_name}.{counter}" in req.cookies:
                encrypted_token += req.cookies[f"{self.cookie_name}.{counter}"]
                counter += 1

        # Or no cookie at all
        else:
            raise MissingTokenError(status_code=401, message=f"Missing JWT cookie: {self.cookie_name}")

        return encrypted_token

    def get_jwt(self):
        return dict(self._token)

    def check_csrf_token(self):
        if self._req.method not in self.csrf_methods:
            return

        if self.csrf_cookie_name not in self._req.cookies:
            raise MissingTokenError(status_code=401, message=f"Missing CSRF token: {self.csrf_cookie_name}")
        if self.csrf_header_name not in self._req.headers:
            raise MissingTokenError(status_code=401, message=f"Missing CSRF header: {self.csrf_header_name}")

        # Validate if it was indeed set by the server
        # See https://github.com/nextauthjs/next-auth/blob/50fe115df6379fffe3f24408a1c8271284af660b/src/core/lib/csrf-token.ts
        # for info on how the CSRF cookie is created
        csrf_token_unquoted = urllib.parse.unquote(self._req.cookies[self.csrf_cookie_name])
        if "|" not in csrf_token_unquoted:
            raise InvalidTokenError(status_code=401, message="Unrecognized CSRF token format")
        csrf_cookie_token, csrf_cookie_hash = csrf_token_unquoted.split("|")
        hasher = SHA256.new()
        hasher.update(bytes(csrf_cookie_token, "ascii"))
        hasher.update(bytes(self.secret.decode(), "ascii"))
        validate_hash = hasher.hexdigest()
        if csrf_cookie_hash != validate_hash:
            raise InvalidTokenError(status_code=401, message="CSRF hash mismatch")

        # Check if the CSRF token in the headers matches the one in the cookie
        csrf_header_token = self._req.headers[self.csrf_header_name]

        if csrf_header_token != csrf_cookie_token:
            raise CSRFMismatchError(status_code=401, message="CSRF Token mismatch")
