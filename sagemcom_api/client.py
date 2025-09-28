"""Client to communicate with Sagemcom F@st internal APIs."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import random
import urllib.parse
from collections.abc import Iterable, Mapping
from types import TracebackType
from typing import Any

import backoff
import humps
from aiohttp import (
    ClientConnectorError,
    ClientOSError,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    ServerDisconnectedError,
    TCPConnector,
)

from .const import API_ENDPOINT, DEFAULT_TIMEOUT, DEFAULT_USER_AGENT, UINT_MAX
from .enums import EncryptionMethod, ErrorCodes
from .exceptions import (
    AccessRestrictionException,
    AuthenticationException,
    BadRequestException,
    InvalidSessionException,
    LoginRetryErrorException,
    LoginTimeoutException,
    MaximumSessionCountException,
    NonWritableParameterException,
    RetryableException,
    UnauthorizedException,
    UnknownException,
    UnknownPathException,
    UnsupportedHostException,
)
from .models import (
    Action,
    Actions,
    Device,
    DeviceInfo,
    LoginAction,
    LogoutAction,
    PortMapping,
)


async def retry_login(invocation: Mapping[str, Any]) -> None:
    """Retry login via backoff if an exception occurs."""
    await invocation["args"][0].login()


def _handle_error(error: dict, actions: Iterable) -> None:
    # Error in one of the actions
    if error["description"] != ErrorCodes.XMO_REQUEST_ACTION_ERR:
        return
    # pylint:disable=fixme
    # TODO How to support multiple actions + error handling?
    for action in actions:
        action_error = action["error"]
        action_error_desc = action_error["description"]
        match action_error_desc:
            case ErrorCodes.XMO_NO_ERR:
                continue
            case ErrorCodes.XMO_AUTHENTICATION_ERR:
                raise AuthenticationException(action_error)
            case ErrorCodes.XMO_ACCESS_RESTRICTION_ERR:
                raise AccessRestrictionException(action_error)
            case ErrorCodes.XMO_NON_WRITABLE_PARAMETER_ERR:
                raise NonWritableParameterException(action_error)
            case ErrorCodes.XMO_UNKNOWN_PATH_ERR:
                raise UnknownPathException(action_error)
            case ErrorCodes.XMO_MAX_SESSION_COUNT_ERR:
                raise MaximumSessionCountException(action_error)
            case ErrorCodes.XMO_LOGIN_RETRY_ERR:
                raise LoginRetryErrorException(action_error)
            case _:
                raise UnknownException(action_error)


# pylint: disable=too-many-instance-attributes
class SagemcomClient:
    """Client to communicate with the Sagemcom API."""

    _auth_key: str | None

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        authentication_method: EncryptionMethod | None = None,
        session: ClientSession | None = None,
        ssl: bool | None = False,
        verify_ssl: bool = True,
    ):
        """
        Create a SagemCom client.

        :param host: the host of your Sagemcom router
        :param username: the username for your Sagemcom router
        :param password: the password for your Sagemcom router
        :param authentication_method: the auth method of your Sagemcom router
        :param session: use a custom session, for example to configure the timeout
        """
        self.host = host
        self.username = username
        self.authentication_method = authentication_method
        self.password = password
        self._current_nonce = None
        self._password_hash = self._generate_hash(password)
        self.protocol = "https" if ssl else "http"

        self._server_nonce = ""
        self._session_id = 0
        self._request_id = -1
        self.api_host = f"{self.protocol}://{self.host}{API_ENDPOINT}"

        self.session = (
            session
            if session
            else ClientSession(
                headers={"User-Agent": f"{DEFAULT_USER_AGENT}"},
                timeout=ClientTimeout(DEFAULT_TIMEOUT),
                connector=TCPConnector(verify_ssl=verify_ssl),
            )
        )

    async def __aenter__(self) -> SagemcomClient:
        """TODO."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close session on exit."""
        await self.close()

    async def close(self) -> None:
        """Close the websession."""
        await self.session.close()

    def __generate_nonce(self, upper_limit=500000):
        """Generate pseudo random number (nonce) to avoid replay attacks."""
        self._current_nonce = math.floor(random.randrange(0, upper_limit))

    def __generate_request_id(self):
        """Generate sequential request ID."""
        self._request_id += 1

    def __generate_md5_nonce_hash(self):
        """Build MD5 with nonce hash token. UINT_MAX is hardcoded in the firmware."""

        def md5(input_string):
            return hashlib.md5(input_string.encode()).hexdigest()

        n = (
            self.__generate_nonce(UINT_MAX)
            if self._current_nonce is None
            else self._current_nonce
        )
        f = 0
        l_nonce = ""
        ha1 = md5(self.username + ":" + l_nonce + ":" + md5(self.password))

        return md5(ha1 + ":" + str(f) + ":" + str(n) + ":JSON:/cgi/json-req")

    def _generate_hash(self, value, authentication_method=None) -> str:
        """Hash value with selected encryption method and return HEX value."""
        auth_method = authentication_method or self.authentication_method

        bytes_object = bytes(value, encoding="utf-8")

        if auth_method == EncryptionMethod.MD5:
            return hashlib.md5(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.SHA512:
            return hashlib.sha512(bytes_object).hexdigest()

        if auth_method == EncryptionMethod.MD5_NONCE:
            return self.__generate_md5_nonce_hash()

        return value

    def _get_credential_hash(self) -> str:
        """Build credential hash."""
        return self._generate_hash(
            f"{self.username}:{self._server_nonce}:{self._password_hash}"
        )

    def __generate_auth_key(self):
        """Build auth key."""
        credential_hash = self._get_credential_hash()
        auth_string = f"{credential_hash}:{self._request_id}:{self._current_nonce}:JSON:{API_ENDPOINT}"
        self._auth_key = self._generate_hash(auth_string)

    def __get_response_error(self, response: ClientResponse) -> dict | None:
        """Retrieve response error from result."""
        try:
            value = response["reply"]["error"]
        except KeyError:
            value = None

        return value

    def __get_response(self, response, index=0):
        """Retrieve response from result."""
        try:
            value = response["reply"]["actions"][index]["callbacks"][0]["parameters"]
        except KeyError:
            value = None

        return value

    def __get_response_value(self, response, index=0):
        """Retrieve response value from value."""
        try:
            value = self.__get_response(response, index)["value"]
        except KeyError:
            value = None
        except IndexError:
            value = None

        # Rewrite result to snake_case
        value = humps.decamelize(value)

        return value

    @backoff.on_exception(
        backoff.expo,
        (ClientConnectorError, ClientOSError, ServerDisconnectedError),
        max_tries=5,
    )
    # pylint: disable=too-many-branches
    async def __post(self, data) -> dict:
        async with self.session.post(self.api_host, data=data) as response:
            if response.status == 400:
                result = await response.text()
                raise BadRequestException(result)

            if response.status == 404:
                result = await response.text()
                raise UnsupportedHostException(result)

            if response.status != 200:
                result = await response.text()
                raise UnknownException(result)

            result = await response.json()
            error = self.__get_response_error(result)

            # No errors
            if error is None or error["description"] in (
                ErrorCodes.XMO_REQUEST_NO_ERR,
                "Ok",
            ):
                return result

            if error["description"] == ErrorCodes.XMO_INVALID_SESSION_ERR:
                self._session_id = 0
                self._server_nonce = ""
                self._request_id = -1
                raise InvalidSessionException(error)

            _handle_error(error, result["reply"]["actions"])

            return result

    async def __api_request_async(self, actions: Actions, priority=False):
        """Build request to the internal JSON-req API."""
        self.__generate_request_id()
        self.__generate_nonce()
        self.__generate_auth_key()

        payload = {
            "request": {
                "id": self._request_id,
                "session-id": int(self._session_id),
                "priority": priority,
                "actions": actions.actions_dict(),
                "cnonce": self._current_nonce,
                "auth-key": self._auth_key,
            }
        }

        form_data = {"req": json.dumps(payload, separators=(",", ":"))}
        try:
            return await self.__post(form_data)
        except (ClientConnectorError, ClientOSError, ServerDisconnectedError) as e:
            raise ConnectionError(str(e)) from e

    async def login(self) -> None:
        """Login to the SagemCom F@st router using a username and password."""
        try:
            response = await self.__api_request_async(
                Actions(LoginAction(self.username)), True
            )
        except asyncio.TimeoutError as exception:
            raise LoginTimeoutException from exception

        data = self.__get_response(response)
        if data["id"] is None or data["nonce"] is None:
            raise UnauthorizedException(data)

        self._session_id = data["id"]
        self._server_nonce = data["nonce"]

    async def logout(self):
        """Log out of the Sagemcom F@st device."""
        await self.__api_request_async(Actions(LogoutAction), False)

        self._session_id = -1
        self._server_nonce = ""
        self._request_id = -1

    async def get_encryption_method(self):
        """Determine which encryption method to use for authentication and set it directly."""

        for encryption_method in EncryptionMethod:
            try:
                self._password_hash = self._generate_hash(
                    self.password, encryption_method
                )

                await self.login()

                self._server_nonce = ""
                self._session_id = 0
                self._request_id = -1
                break

            except RetryableException:
                pass
        else:
            return None
        self.authentication_method = encryption_method
        return encryption_method

    @backoff.on_exception(
        backoff.expo, RetryableException, max_tries=1, on_backoff=retry_login
    )
    async def get_value_by_xpath(self, xpath: str, options: dict | None = None) -> dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param options: optional options
        """
        actions = Actions(
            Action(0, "getValue", xpath=urllib.parse.quote(xpath), options=options)
        )

        response = await self.__api_request_async(actions, False)
        data = self.__get_response_value(response)

        return data

    @backoff.on_exception(
        backoff.expo, RetryableException, max_tries=1, on_backoff=retry_login
    )
    async def get_values_by_xpaths(
        self, xpaths: dict, options: dict | None = None
    ) -> dict:
        """
        Retrieve raw values from router using XPath.

        :param xpaths: Dict of key to xpath expression
        :param options: optional options
        """
        actions = Actions(
            Action(i, "getValue", xpath=urllib.parse.quote(xpath), options=options)
            for i, xpath in enumerate(xpaths.values())
        )

        response = await self.__api_request_async(actions, False)
        values = [self.__get_response_value(response, i) for i in range(len(xpaths))]
        data = dict(zip(xpaths.keys(), values))

        return data

    @backoff.on_exception(
        backoff.expo, RetryableException, max_tries=1, on_backoff=retry_login
    )
    async def set_value_by_xpath(
        self, xpath: str, value: str, options: dict | None = None
    ) -> dict:
        """
        Retrieve raw value from router using XPath.

        :param xpath: path expression
        :param value: value
        :param options: optional options
        """
        action = Action(
            0,
            "setValue",
            xpath=urllib.parse.quote(xpath),
            parameters={"value": str(value)},
            options=options,
        )

        response = await self.__api_request_async(Actions(action), False)

        return response

    @backoff.on_exception(
        backoff.expo, RetryableException, max_tries=1, on_backoff=retry_login
    )
    async def get_device_info(self) -> DeviceInfo:
        """Retrieve information about Sagemcom F@st device."""
        try:
            data = await self.get_value_by_xpath("Device/DeviceInfo")
            return DeviceInfo(**data["device_info"])
        except UnknownPathException:
            data = await self.get_values_by_xpaths(
                {
                    "mac_address": "Device/DeviceInfo/MACAddress",
                    "model_name": "Device/DeviceInfo/ModelNumber",
                    "model_number": "Device/DeviceInfo/ProductClass",
                    "product_class": "Device/DeviceInfo/ProductClass",
                    "serial_number": "Device/DeviceInfo/SerialNumber",
                    "software_version": "Device/DeviceInfo/SoftwareVersion",
                }
            )
            data["manufacturer"] = "Sagemcom"

        return DeviceInfo(**data)

    @backoff.on_exception(
        backoff.expo, RetryableException, max_tries=1, on_backoff=retry_login
    )
    async def get_hosts(self, only_active: bool = False) -> list[Device]:
        """Retrieve hosts connected to Sagemcom F@st device."""

        def _filter(data: dict) -> bool:
            if only_active:
                return data.get("active", False) is True
            return True

        data = await self.get_value_by_xpath(
            "Device/Hosts/Hosts", options={"capability-flags": {"interface": True}}
        )

        return [Device(**d) for d in data if _filter(d)]

    @backoff.on_exception(
        backoff.expo, RetryableException, max_tries=1, on_backoff=retry_login
    )
    async def get_port_mappings(self) -> list[PortMapping]:
        """Retrieve configured Port Mappings on Sagemcom F@st device."""
        data = await self.get_value_by_xpath("Device/NAT/PortMappings")
        return [PortMapping(**p) for p in data]

    @backoff.on_exception(
        backoff.expo, RetryableException, max_tries=1, on_backoff=retry_login
    )
    async def reboot(self):
        """Reboot Sagemcom F@st device."""
        action = Action(
            id=0,
            method="reboot",
            xpath="Device",
            parameters={"source": "GUI"},
        )

        response = await self.__api_request_async(Actions(action), False)
        data = self.__get_response_value(response)

        return data
