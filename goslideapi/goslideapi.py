"""Python wrapper for Go Slide API."""

import aiohttp
import asyncio
import hashlib
import json
import logging
import os
import re
import time

_LOGGER = logging.getLogger(__name__)

# API Link: https://documenter.getpostman.com/view/6223391/S1Lu2pSf
BASEURL = "https://api.goslide.io/api/{}"
DEFAULT_TIMEOUT_CLOUD = 10
DEFAULT_TIMEOUT_LOCAL = 5


class AuthenticationFailed(Exception):
    """Error to indicate that authentication with Slide API has failed."""

    pass


class ClientConnectionError(Exception):
    """Error to indicate to connection issues with the Slide API."""

    pass


class ClientTimeoutError(Exception):
    """Error to indicate to timeout issues with the Slide API."""

    pass


class DigestAuthCalcError(Exception):
    """Error to indicate an error that the digest authentication calculation went wrong."""

    pass


class GoSlideCloud:
    """API Wrapper for the Go Slide devices."""

    def __init__(
        self,
        username,
        password,
        timeout=DEFAULT_TIMEOUT_CLOUD,
        url=BASEURL,
        authexception=True,
        verify_ssl=True,
    ):
        """Create the object with required parameters."""
        self._username = username
        self._password = password
        self._timeout = timeout
        self._url = url
        self._authenticated = False
        self._accesstoken = ""
        self._authfailed = False
        self._expiretoken = None
        self._authexception = authexception
        self._requestcount = 0
        self._verify_ssl = verify_ssl

    async def _dorequest(self, reqtype, urlsuffix, data=None):
        """HTTPS request handler."""

        # Increment request counter for logging purpose
        self._requestcount += 1
        if self._requestcount > 99999:
            self._requestcount = 1

        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        self._authfailed = False

        if self._authenticated:
            headers["Authorization"] = "Bearer {}".format(self._accesstoken)

        _LOGGER.debug(
            "REQ-C%d: API=%s, type=%s, data=%s",
            self._requestcount,
            self._url.format(urlsuffix),
            reqtype,
            json.dumps(data),
        )

        # Set a reasonable timeout, otherwise it can take > 300 seconds
        atimeout = aiohttp.ClientTimeout(total=self._timeout)

        # Known error codes from the Cloud API:
        # 401 - Authentication failed
        # 403 - Forbidden, most likely we want to control a slide
        #       which isn't in our account
        # 404 - Can't find API endpoint
        # 422 - The given data was invalid
        # 424 - If one or multiple Slides are offline. The 'device_info'
        #       will contain code=500, 'Device unavailable' for those slides
        # aiohttp.client_exceptions.ClientConnectorError: No IP, timeout

        try:
            connector = None
            if not self._verify_ssl:
                connector = aiohttp.TCPConnector(verify_ssl=False)

            async with aiohttp.request(
                reqtype,
                self._url.format(urlsuffix),
                headers=headers,
                json=data,
                timeout=atimeout,
                connector=connector,
            ) as resp:
                if resp.status in [200, 424]:
                    textdata = await resp.text()
                    _LOGGER.debug(
                        "RES-C%d: API=%s, type=%s, HTTPCode=%s, Data=%s",
                        self._requestcount,
                        self._url.format(urlsuffix),
                        reqtype,
                        resp.status,
                        textdata,
                    )

                    try:
                        jsondata = json.loads(textdata)
                    except json.decoder.JSONDecodeError:
                        _LOGGER.error(
                            "RES-C%d: API=%s, type=%s, INVALID JSON=%s",
                            self._requestcount,
                            self._url.format(urlsuffix),
                            reqtype,
                            textdata,
                        )
                        jsondata = None

                    return jsondata
                else:
                    textdata = await resp.text()
                    _LOGGER.error(
                        "RES-C%d: API=%s, type=%s, HTTPCode=%s, Data=%s",
                        self._requestcount,
                        self._url.format(urlsuffix),
                        reqtype,
                        resp.status,
                        textdata,
                    )

                    if resp.status in [401, 422]:
                        # Raise exception, normally used by Home Assistant
                        if self._authexception:
                            raise AuthenticationFailed

                        self._authfailed = True

                    return None
        except (
            aiohttp.client_exceptions.ClientConnectionError,
            aiohttp.client_exceptions.ClientConnectorError,
        ) as err:
            raise ClientConnectionError(str(err)) from None
        except asyncio.TimeoutError as err:
            raise ClientTimeoutError("Connection Timeout") from None

    async def _request(self, reqtype, urlsuffix, data=None):
        """Retry authentication around dorequest."""
        resp = await self._dorequest(reqtype, urlsuffix, data)

        if self._authfailed:
            _LOGGER.warning("Retrying request, because authentication " "failed")

            resp = None
            if await self.login():
                resp = await self._dorequest(reqtype, urlsuffix, data)
                if self._authfailed:
                    _LOGGER.error("Failed request. API=%s", self._url.format(urlsuffix))

        return resp

    async def _checkauth(self):
        """Check if we are authenticated."""
        if self._authenticated:
            from datetime import datetime, timezone

            if self._expiretoken is not None:
                diff = self._expiretoken - datetime.now(timezone.utc)

                # Reauthenticate if token is less then 7 days valid
                if diff.days <= 7:
                    _LOGGER.info(
                        "Authentication token will expire in %s " "days, renewing it",
                        int(diff.days),
                    )
                    return await self.login()

                _LOGGER.debug("Authentication token valid for %s days", int(diff.days))

            return True

        return await self.login()

    async def login(self):
        """Login to the Cloud API and retrieve a token."""
        from datetime import datetime

        self._authenticated = False
        self._accesstoken = ""

        # Call dorequest, because if auth fails, it won't work second time.
        result = await self._dorequest(
            "POST", "auth/login", {"email": self._username, "password": self._password}
        )
        if result:
            if "access_token" in result:
                self._authenticated = True
                self._accesstoken = result["access_token"]

                # Token format is in UTC
                if "expires_at" in result:
                    self._expiretoken = datetime.strptime(
                        result["expires_at"] + " +0000", "%Y-%m-%d %H:%M:%S %z"
                    )
                    _LOGGER.debug(
                        "Authentication token expiry: %s", result["expires_at"]
                    )
                else:
                    self._expiretoken = None
                    _LOGGER.error(
                        "Auth login JSON is missing the " "'expires_at' field in %s",
                        result,
                    )

        return self._authenticated

    async def logout(self):
        """Logout of the Cloud API."""
        resp = False

        if self._authenticated:
            # Call dorequest, because we don't want retry
            resp = await self._dorequest("POST", "auth/logout")
            resp = bool(resp)

        self._authenticated = False
        self._accesstoken = ""

        return resp

    async def slides_overview(self):
        """Retrieve the slides overview list."""
        # {
        #   "slides": [
        #     {
        #       "id": 1,
        #       "device_name": "Living Room",
        #       "slide_setup": "middle",
        #       "curtain_type": "rail",
        #       "device_id": "slide_300000000000",
        #       "household_id": 1,
        #       "zone_id": 1,
        #       "touch_go": true,
        #       "device_info": {
        #         "pos": 0.0
        #       },
        #       "routines": [],
        #     },
        #     {
        #       "id": 2,
        #       "device_name": "Study Room",
        #       "slide_setup": "middle",
        #       "curtain_type": "rail",
        #       "device_id": "slide_300000000001",
        #       "household_id": 1,
        #       "zone_id": 2,
        #       "touch_go": false,
        #       "device_info": {
        #         "message": "No response from device.",
        #         "code": 500
        #       },
        #       "routines": {
        #         "message": "No response from device.",
        #         "code": 500
        #     },
        #     {...},
        #   ]
        # }
        if not await self._checkauth():
            return None

        result = await self._request("GET", "slides/overview")
        if result and "slides" in result:
            return result["slides"]

        _LOGGER.error("Missing key 'slides' in JSON=%s", json.dumps(result))
        return None

    async def slide_info(self, slideid):
        """Retrieve the slide info."""
        # The format is:
        # {
        #   "data": {
        #     "board_rev": 1,
        #     "calib_time": 10239,
        #     "curtain_type": 0, # deprecated
        #     "device_name": "Living Room", # deprecated
        #     "mac": "300000000000",
        #     "pos": 0.0,
        #     "slide_id": "slide_300000000000",
        #     "touch_go": true,
        #     "zone_name": "" # deprecated
        #   },
        #   "error": null
        # }
        if not await self._checkauth():
            return None

        result = await self._request("GET", "slide/{}/info".format(slideid))
        if result and "data" in result:
            return result["data"]

        _LOGGER.error("Missing key 'data' in JSON=%s", json.dumps(result))
        return None

    async def slide_config(self, slideid):
        """Retrieve the slide configuration."""
        # The format is:
        # {
        #   tbd
        #   "error": null
        # }
        if not await self._checkauth():
            return None

        result = await self._request("GET", "slides/{}".format(slideid))
        if result and "data" in result:
            return result["data"]

        _LOGGER.error("Missing key 'data' in JSON=%s", json.dumps(result))
        return None

    async def slide_get_position(self, slideid):
        """Retrieve the slide position."""
        result = await self.slide_info(slideid)
        if result:
            if "pos" in result:
                return result["pos"]
            _LOGGER.error(
                "SlideGetPosition: Missing key 'pos' in JSON=%s", json.dumps(result)
            )

        return None

    async def slide_set_position(self, slideid, posin):
        """Set the slide position, only 0.0 - 1.0 is allowed."""
        try:
            pos = float(posin)
        except ValueError:
            _LOGGER.error("SlideSetPosition: '%s' has to be numeric", posin)
            return False

        if pos < 0 or pos > 1:
            _LOGGER.error("SlideSetPosition: '%s' has to be between 0.0-1.0", pos)
            return False

        if not await self._checkauth():
            return False

        resp = await self._request(
            "POST", "slide/{}/position".format(slideid), {"pos": pos}
        )
        return bool(resp)

    async def slide_open(self, slideid):
        """Open a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request(
            "POST", "slide/{}/position".format(slideid), {"pos": 0.0}
        )
        return bool(resp)

    async def slide_close(self, slideid):
        """Close a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request(
            "POST", "slide/{}/position".format(slideid), {"pos": 1.0}
        )
        return bool(resp)

    async def slide_stop(self, slideid):
        """Stop a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request("POST", "slide/{}/stop".format(slideid))
        return bool(resp)

    async def slide_calibrate(self, slideid):
        """Calibrate a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request("POST", "slide/{}/calibrate".format(slideid))
        return bool(resp)

    async def household_get(self):
        """Return household information."""
        if not await self._checkauth():
            return False

        resp = await self._request("GET", "households")
        return resp

    async def household_set(self, name, address, lat, lon):
        """Set household information."""
        if not await self._checkauth():
            return False

        resp = await self._request(
            "PATCH",
            "households",
            {"name": name, "address": address, "lat": lat, "lon": lon},
        )
        return bool(resp)


class GoSlideLocal:
    """API Wrapper for the Go Slide devices, local connectivity."""

    def __init__(self, timeout=DEFAULT_TIMEOUT_LOCAL, authexception=True):
        """Create the object with required parameters."""
        self._timeout = timeout
        self._authexception = authexception
        self._cnoncecount = 0
        self._requestcount = 0
        self._slide_passwd = {}
        self._slide_api = {}

    def _md5_utf8(self, x):
        if isinstance(x, str):
            x = x.encode("utf-8")
        return hashlib.md5(x).hexdigest()

    def _make_digest_auth(self, username, password, method, uri, my_auth):
        nonce = re.findall(r'nonce="(.*?)"', my_auth)[0]
        realm = re.findall(r'realm="(.*?)"', my_auth)[0]
        qop = re.findall(r'qop="(.*?)"', my_auth)[0]
        nc = "00000001"

        # Generate cnonce value
        self._cnoncecount += 1
        s = str(self._cnoncecount).encode("utf-8")
        s += nonce.encode("utf-8")
        s += time.ctime().encode("utf-8")
        s += os.urandom(8)

        cnonce = hashlib.sha1(s).hexdigest()[:8]

        # calculate HA1
        HA1 = self._md5_utf8(username + ":" + realm + ":" + password)

        # calculate HA2
        HA2 = self._md5_utf8(method + ":" + uri)

        if qop == "auth" or "auth" in qop.split(","):
            # calculate client response
            response = self._md5_utf8(
                HA1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + HA2
            )
        else:
            # Raise error, this situation shouldn't happe. Slide should always use qop=auth
            _LOGGER.error("Invalid digest authentication qop=%s found", qop)
            raise DigestAuthCalcError

        return 'Digest username="{}", realm="{}", nonce="{}", uri="{}", algorithm="MD5", qop=auth, nc={}, cnonce="{}", response="{}"'.format(
            username, realm, nonce, uri, nc, cnonce, response
        )

    async def _dorequest(self, reqtype, url, digestauth=None, data=None):
        """HTTP request handler."""

        # Increment request counter for logging purpose
        self._requestcount += 1
        if self._requestcount > 99999:
            self._requestcount = 1

        headers = {"Content-Type": "application/json", "Accept": "application/json"}

        if digestauth:
            headers["Authorization"] = digestauth

        _LOGGER.debug(
            "REQ-L%d: API=%s, type=%s, data=%s",
            self._requestcount,
            url,
            reqtype,
            json.dumps(data),
        )

        # Set a reasonable timeout, otherwise it can take > 300 seconds
        atimeout = aiohttp.ClientTimeout(total=self._timeout)

        # Known error codes from the Local API:
        # 401 - Digest challenge
        # aiohttp.client_exceptions.ClientConnectorError: No IP, timeout

        try:
            async with aiohttp.request(
                reqtype, url, headers=headers, json=data, timeout=atimeout
            ) as resp:
                if resp.status == 200:
                    textdata = await resp.text()
                    _LOGGER.debug(
                        "RES-L%d: API=%s, type=%s, HTTPCode=%s, Data=%s",
                        self._requestcount,
                        url,
                        reqtype,
                        resp.status,
                        textdata,
                    )

                    try:
                        jsondata = json.loads(textdata)
                    except json.decoder.JSONDecodeError:
                        _LOGGER.error(
                            "RES-L%d: API=%s, type=%s, INVALID JSON=%s",
                            self._requestcount,
                            url,
                            reqtype,
                            textdata,
                        )
                        jsondata = None

                    return resp.status, jsondata

                if resp.status == 401:

                    if "WWW-Authenticate" in resp.headers:
                        headerdata = resp.headers["WWW-Authenticate"]
                    else:
                        headerdata = None

                    _LOGGER.debug(
                        "RES-L%d: API=%s, type=%s, HTTPCode=%s, WWW-Authenticate=%s",
                        self._requestcount,
                        url,
                        reqtype,
                        resp.status,
                        headerdata,
                    )

                    return resp.status, headerdata
                else:
                    textdata = await resp.text()
                    _LOGGER.error(
                        "RES-L%d: API=%s, type=%s, HTTPCode=%s, Data=%s",
                        self._requestcount,
                        url,
                        reqtype,
                        resp.status,
                        textdata,
                    )

                    return resp.status, None
        except (
            aiohttp.client_exceptions.ClientConnectionError,
            aiohttp.client_exceptions.ClientConnectorError,
        ) as err:
            raise ClientConnectionError(str(err)) from None
        except asyncio.TimeoutError as err:
            raise ClientTimeoutError("Connection Timeout") from None

    async def _request(self, hostname, password, apiversion, reqtype, uri, data=None):
        """Digest authentication using dorequest."""

        # Local API uses digest authentication:
        # https://en.wikipedia.org/wiki/Digest_access_authentication

        # We need to send 2 requests:
        #  - first request will result in a 401 with a response header "WWW-Authenticate"
        #  - second request will add "Authorization" header calculated from "WWW-Authenticate"

        # format URL with hostname/ip and uri value
        url = "http://{}{}".format(hostname, uri)

        # First request, should return a 401 error for v1
        # First request is not required for v2

        # Default is version 1, when we do WWW-Authentication
        if apiversion == 1:

            # do request to obtain a WWW-authentication header:
            respstatus, resptext = await self._dorequest(reqtype, url, data=data)
            
            # Authentication was not needed. Slide has been upgraded.
            if respstatus == 200:
                _LOGGER.debug("Slide %s updated to API version 2", hostname)
                self._slide_api[hostname] = 2
                return resptext

            # Otherwise, we should have a 401 response
            if respstatus == 401:

                # The resptext contains the WWW-Authentication header
                auth = self._make_digest_auth("user", password, reqtype, uri, resptext)

                respstatus, resptext = await self._dorequest(
                    reqtype, url, digestauth=auth, data=data
                )

                if respstatus == 200:
                    return resptext

                # Anything else is an error
                _LOGGER.error(
                    "Failed request with Local API Digest Authentication challenge. HTTPCode=%s",
                    respstatus,
                )
            else:
                # We expected a 401 Digest Auth here
                _LOGGER.error(
                    "Failed request with Local API v1. Received HTTPCode=%s, expected HTTPCode=401. Maybe try switching to api version 2?",
                    respstatus,
                )

        elif apiversion == 2:

            respstatus, resptext = await self._dorequest(reqtype, url, data=data)

            if respstatus == 200:
                return resptext

            # Anything else is an error
            _LOGGER.error(
                "Failed request Local API v2. HTTPCode=%s",
                respstatus,
            )

        else:
            _LOGGER.error(
                "Only v1 and v2 is supported.",
            )

        return None

    async def slide_add(self, hostname, password, api=2):
        """Add slide to internal table, then you can use the local API."""
        self._slide_passwd[hostname] = password
        self._slide_api[hostname] = api

    async def slide_del(self, hostname):
        """Delete slide from internal table."""
        if hostname in self._slide_passwd:
            self._slide_passwd.remove(hostname)
        if hostname in self._slide_api:
            self._slide_api.remove(hostname)
        else:
            _LOGGER.error("Tried to delete none-existing '%s' from list", hostname)

    async def slide_list(self):
        """List all registered slides."""
        return list(self._slide_passwd.keys())

    async def _slide_exist(self, hostname):
        """Function to check if slide exist in internal table."""
        if hostname in self._slide_passwd:
            return True
        else:
            _LOGGER.error(
                "Cannot find hostname '%s' in list, forgot to call 'slide_add'?",
                hostname,
            )
            return False

    async def slide_info(self, hostname):
        """Retrieve the slide info."""
        # The format is:
        # {
        #   "slide_id": "slide_300000000000",
        #   "mac": "300000000000",
        #   "board_rev": 1,
        #   "device_name": "",
        #   "zone_name": "",
        #   "curtain_type": 0,
        #   "calib_time": 10239,
        #   "pos": 0.0,
        #   "touch_go": true
        # }

        if not await self._slide_exist(hostname):
            return None

        result = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.GetInfo",
        )

        return result

    async def slide_get_position(self, hostname):
        """Retrieve the slide position."""
        result = await self.slide_info(hostname)
        if result:
            if "pos" in result:
                return result["pos"]
            _LOGGER.error(
                "SlideGetPosition: Missing key 'pos' in JSON=%s", json.dumps(result)
            )

        return None

    async def slide_set_position(self, hostname, posin):
        """Set the slide position, only 0.0 - 1.0 is allowed."""
        try:
            pos = float(posin)
        except ValueError:
            _LOGGER.error("SlideSetPosition: '%s' has to be numeric", posin)
            return False

        if pos < 0 or pos > 1:
            _LOGGER.error("SlideSetPosition: '%s' has to be between 0.0-1.0", pos)
            return False

        if not await self._slide_exist(hostname):
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.SetPos",
            data={"pos": pos},
        )
        return bool(resp)

    async def slide_open(self, hostname):
        """Open a slide."""
        if not await self._slide_exist(hostname):
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.SetPos",
            data={"pos": 0.0},
        )
        return bool(resp)

    async def slide_close(self, hostname):
        """Close a slide."""
        if not await self._slide_exist(hostname):
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.SetPos",
            data={"pos": 1.0},
        )
        return bool(resp)

    async def slide_stop(self, hostname):
        """Stop a slide."""
        if not await self._slide_exist(hostname):
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.Stop",
        )
        return bool(resp)

    async def slide_calibrate(self, hostname):
        """Calibrate a slide."""
        if not await self._slide_exist(hostname):
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.Calibrate",
        )
        return bool(resp)

    async def slide_configwifi(self, hostname, ssid, password):
        """Configure slide wifi."""
        if not await self._slide_exist(hostname):
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.Config.Wifi",
            data={"ssid": ssid, "pass": password},
        )
        return bool(resp)

    async def slide_get_touchgo(self, hostname):
        """Retrieve the slide TouchGo setting."""
        result = await self.slide_info(hostname)
        if result:
            if "touch_go" in result:
                return result["touch_go"]
            _LOGGER.error(
                "SlideGetTouchGo: Missing key 'touch_go' in JSON=%s", json.dumps(result)
            )

        return None

    async def slide_set_touchgo(self, hostname, value):
        """Change Touch-Go of a slide."""
        if not await self._slide_exist(hostname):
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.touchGo",
            data={"touch_go": value},
        )
        return bool(resp)

    async def slide_set_motor_strength(self, hostname,  maxcurrent, calib_current):
        """Change Motor Strength a slide."""
        if not await self._slide_exist(hostname):
            return False

        # *** Do NOT go over 1450 ***
        # Light: maxcurrent=900, calib_current=850
        # Medium: maxcurrent=1250, calib_current=1200
        # Strong: maxcurrent=1500, calib_current=1450

        if maxcurrent > 1500:
            _LOGGER.error(
                "Slide.Config.Motor: 'maxcurrent=%s' has to be lower than 1500",
                maxcurrent,
            )
            return False

        if calib_current > 1450:
            _LOGGER.error(
                "Slide.Config.Motor: 'calib_current=%s' has to be lower than 1450",
                calib_current,
            )
            return False

        resp = await self._request(
            hostname,
            self._slide_passwd[hostname],
            self._slide_api[hostname],
            "POST",
            "/rpc/Slide.Config.Motor",
            data={"maxcurrent": maxcurrent, "calib_current": calib_current},
        )
        return bool(resp)
