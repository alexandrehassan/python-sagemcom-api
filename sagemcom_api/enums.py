"""Enums for the Sagemcom F@st client."""

from enum import unique
import sys

# Since we support Python versions lower than 3.11, we use
# a backport for StrEnum when needed.
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from backports.strenum import StrEnum


@unique
class EncryptionMethod(StrEnum):
    """Encryption method defining the password hash."""

    MD5 = "MD5"
    MD5_NONCE = "MD5_NONCE"
    SHA512 = "SHA512"


@unique
class ErrorCodes(StrEnum):
    XMO_ACCESS_RESTRICTION_ERR = "XMO_ACCESS_RESTRICTION_ERR"
    XMO_AUTHENTICATION_ERR = "XMO_AUTHENTICATION_ERR"
    XMO_INVALID_SESSION_ERR = "XMO_INVALID_SESSION_ERR"
    XMO_NON_WRITABLE_PARAMETER_ERR = "XMO_NON_WRITABLE_PARAMETER_ERR"
    XMO_NO_ERR = "XMO_NO_ERR"
    XMO_REQUEST_ACTION_ERR = "XMO_REQUEST_ACTION_ERR"
    XMO_REQUEST_NO_ERR = "XMO_REQUEST_NO_ERR"
    XMO_UNKNOWN_PATH_ERR = "XMO_UNKNOWN_PATH_ERR"
    XMO_MAX_SESSION_COUNT_ERR = "XMO_MAX_SESSION_COUNT_ERR"
    XMO_LOGIN_RETRY_ERR = "XMO_LOGIN_RETRY_ERR"
