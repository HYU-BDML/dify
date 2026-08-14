"""Firebase ID-token verification for the Boram fork (AUTH-01).

The console login path exchanges a Firebase ID token for a Dify console session.
This module owns the *verification* half: it lazily initialises the Firebase Admin
SDK and validates an ID token, enforcing three independent gates before an account
is ever provisioned:

1. The token is a genuine, non-revoked Firebase ID token whose ``aud`` claim is
   pinned to ``FIREBASE_PROJECT_ID``.
2. The Firebase account's e-mail is verified.
3. The e-mail belongs to the ``hanyang.ac.kr`` domain by *exact* match.

The domain check uses exact equality on the final ``@`` segment and refuses any
address that does not contain exactly one ``@``. It deliberately never uses
``str.endswith`` -- ``endswith("hanyang.ac.kr")`` would wave through hostile
domains such as ``evil-hanyang.ac.kr``.

``firebase_admin`` is imported inside the functions (lazy) so that importing this
module -- and byte-compiling it -- never requires the package to be installed.
"""

import threading

from configs import dify_config

#: The single allowed e-mail domain. Compared by exact equality, never suffix.
ALLOWED_EMAIL_DOMAIN = "hanyang.ac.kr"

#: Provider key used for AccountIntegrate rows and openid lookups.
FIREBASE_PROVIDER = "firebase"

_init_lock = threading.Lock()
_initialized = False


class FirebaseError(Exception):
    """Base class for every Firebase exchange failure."""


class FirebaseConfigError(FirebaseError):
    """Firebase is not configured on the server (fail-closed)."""


class FirebaseTokenError(FirebaseError):
    """The supplied Firebase ID token is missing, malformed, expired, or revoked."""


class FirebaseEmailNotVerifiedError(FirebaseError):
    """The Firebase account exists but its e-mail is not verified."""


class FirebaseDomainError(FirebaseError):
    """The verified e-mail is outside the allowed domain."""


def _ensure_initialized() -> None:
    """Initialise the default Firebase Admin app exactly once (thread-safe)."""
    global _initialized
    if _initialized:
        return

    with _init_lock:
        if _initialized:
            return

        import firebase_admin
        from firebase_admin import credentials

        try:
            firebase_admin.get_app()
        except ValueError:
            # No default app yet -> create one.
            cred = None
            if dify_config.FIREBASE_CREDENTIALS_JSON:
                cred = credentials.Certificate(dify_config.FIREBASE_CREDENTIALS_JSON)

            options: dict[str, str] = {}
            if dify_config.FIREBASE_PROJECT_ID:
                # Pinning projectId makes verify_id_token enforce the aud claim.
                options["projectId"] = dify_config.FIREBASE_PROJECT_ID

            firebase_admin.initialize_app(cred, options)

        _initialized = True


def verify_and_extract(id_token: str) -> tuple[str, str]:
    """Verify a Firebase ID token and return ``(uid, email)``.

    Raises a specific :class:`FirebaseError` subclass for each failure mode so the
    caller can log precisely while always failing closed.
    """
    if not id_token:
        raise FirebaseTokenError("Missing Firebase ID token.")

    _ensure_initialized()

    from firebase_admin import auth as firebase_auth

    try:
        decoded = firebase_auth.verify_id_token(id_token, check_revoked=True)
    except Exception as e:  # noqa: BLE001 - normalise every SDK error into our taxonomy
        raise FirebaseTokenError("Invalid or revoked Firebase ID token.") from e

    if decoded.get("email_verified") is not True:
        raise FirebaseEmailNotVerifiedError("Firebase e-mail is not verified.")

    email = decoded.get("email")
    if not email or not isinstance(email, str):
        raise FirebaseEmailNotVerifiedError("Firebase token carries no e-mail address.")
    email = email.strip().lower()

    # Reject anything that is not exactly local@domain: 0 or 2+ '@' are refused.
    if email.count("@") != 1:
        raise FirebaseDomainError("Malformed e-mail address.")

    domain = email.rsplit("@", 1)[1]
    if domain != ALLOWED_EMAIL_DOMAIN:
        raise FirebaseDomainError(f"E-mail domain '{domain}' is not allowed.")

    uid = decoded.get("uid") or decoded.get("sub")
    if not uid or not isinstance(uid, str):
        raise FirebaseTokenError("Firebase token carries no uid.")

    return uid, email
