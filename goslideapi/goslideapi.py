"""Python wrapper for Go Slide API."""

import json
import logging
import aiohttp

_LOGGER = logging.getLogger(__name__)

# API Link: https://documenter.getpostman.com/view/6223391/S1Lu2pSf
BASEURL = 'https://api.goslide.io/api/{}'
DEFAULT_TIMEOUT = 30


class GoSlideCloud:
    """API Wrapper for the Go Slide devices."""

    def __init__(self, username, password, timeout=DEFAULT_TIMEOUT, url=BASEURL):
        """Create the object with required parameters."""
        self._username = username
        self._password = password
        self._timeout = timeout
        self._url = url
        self._authenticated = False
        self._accesstoken = ''
        self._authfailed = False
        self._expiretoken = None

    async def _dorequest(self, reqtype, urlsuffix, data=None):
        """HTTPS request handler."""
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json'}

        self._authfailed = False

        if self._authenticated:
            headers['Authorization'] = 'Bearer {}'.format(self._accesstoken)

        _LOGGER.debug("REQ: API=%s, type=%s, data=%s",
                      self._url.format(urlsuffix), reqtype, json.dumps(data))

        # Set a reasonable timeout, otherwise it can take > 300 seconds
        atimeout = aiohttp.ClientTimeout(total=self._timeout)

        # Known error codes from the Cloud API:
        # 401 - Authentication failed
        # 403 - Forbidden, most likely we want to control a slide
        #       which isn't in our account
        # 404 - Can't find API endpoint
        # 424 - If one or multiple Slides are offline. The 'device_info'
        #       will contain code=500, 'Device unavailable' for those slides
        # aiohttp.client_exceptions.ClientConnectorError: No IP, timeout

        async with aiohttp.request(reqtype,
                                   self._url.format(urlsuffix),
                                   headers=headers,
                                   json=data,
                                   timeout=atimeout) as resp:
            if resp.status in [200, 424]:
                textdata = await resp.text()
                _LOGGER.debug("RES: API=%s, type=%s, HTTPCode=%s, Data=%s",
                              self._url.format(urlsuffix), reqtype,
                              resp.status, textdata)

                try:
                    jsondata = json.loads(textdata)
                except json.decoder.JSONDecodeError:
                    _LOGGER.error("RES: API=%s, type=%s, INVALID JSON=%s",
                                  self._url.format(urlsuffix), reqtype,
                                  textdata)
                    jsondata = None

                return jsondata
            else:
                textdata = await resp.text()
                _LOGGER.error("RES: API=%s, type=%s, HTTPCode=%s, Data=%s",
                              self._url.format(urlsuffix), reqtype,
                              resp.status, textdata)

                if resp.status == 401:
                    self._authfailed = True

                return None

    async def _request(self, reqtype, urlsuffix, data=None):
        """Retry authentication around dorequest."""
        resp = await self._dorequest(reqtype, urlsuffix, data)

        if self._authfailed:
            _LOGGER.warning("Retrying request, because authentication "
                            "failed")

            resp = None
            if await self.login():
                resp = await self._dorequest(reqtype, urlsuffix, data)
                if self._authfailed:
                    _LOGGER.error("Failed request. API=%s",
                                  self._url.format(urlsuffix))

        return resp

    async def _checkauth(self):
        """Check if we are authenticated."""
        if self._authenticated:
            from datetime import datetime, timezone

            if self._expiretoken is not None:
                diff = self._expiretoken - datetime.now(timezone.utc)

                # Reauthenticate if token is less then 7 days valid
                if diff.days <= 7:
                    _LOGGER.info("Authentication token will expire in %s "
                                 "days, renewing it", int(diff.days))
                    return await self.login()

                _LOGGER.debug("Authentication token valid for %s days",
                              int(diff.days))

            return True

        return await self.login()

    async def login(self):
        """Login to the Cloud API and retrieve a token."""
        from datetime import datetime

        self._authenticated = False
        self._accesstoken = ''

        # Call dorequest, because if auth fails, it won't work second time.
        result = await self._dorequest('POST',
                                       'auth/login',
                                       {'email': self._username,
                                        'password': self._password})
        if result:
            if 'access_token' in result:
                self._authenticated = True
                self._accesstoken = result['access_token']

                # Token format is in UTC
                if 'expires_at' in result:
                    self._expiretoken = \
                        datetime.strptime(result['expires_at'] + ' +0000',
                                          '%Y-%m-%d %H:%M:%S %z')
                    _LOGGER.debug("Authentication token expiry: %s",
                                  result['expires_at'])
                else:
                    self._expiretoken = None
                    _LOGGER.error("Auth login JSON is missing the "
                                  "'expires_at' field in %s", result)

        return self._authenticated

    async def logout(self):
        """Logout of the Cloud API."""
        resp = False

        if self._authenticated:
            # Call dorequest, because we don't want retry
            resp = await self._dorequest('POST', 'auth/logout')
            resp = bool(resp)

        self._authenticated = False
        self._accesstoken = ''

        return resp

    async def slidesoverview(self):
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

        result = await self._request('GET', 'slides/overview')
        if result and 'slides' in result:
            return result['slides']

        _LOGGER.error("Missing key 'slides' in JSON=%s", json.dumps(result))
        return None

    async def slideinfo(self, slideid):
        """Retrieve the slide info."""
        # The format is:
        # {
        #   "data": {
        #     "board_rev": 1,
        #     "calib_time": 10239,
        #     "curtain_type": 0,
        #     "device_name": "Living Room",
        #     "mac": "300000000000",
        #     "pos": 0.0,
        #     "slide_id": "slide_300000000000",
        #     "touch_go": true,
        #     "zone_name": ""
        #   },
        #   "error": null
        # }
        if not await self._checkauth():
            return None

        result = await self._request('GET', 'slide/{}/info'.format(slideid))
        if result and 'data' in result:
            return result['data']

        _LOGGER.error("Missing key 'data' in JSON=%s", json.dumps(result))
        return None

    async def slidegetposition(self, slideid):
        """Retrieve the slide position."""
        result = await self.slideinfo(slideid)
        if result:
            if 'pos' in result:
                return result['pos']
            _LOGGER.error("SlideGetPosition: Missing key 'pos' in JSON=%s",
                          json.dumps(result))

        return None

    async def slidesetposition(self, slideid, posin):
        """Set the slide position, only 0.0 - 1.0 is allowed."""
        try:
            pos = float(posin)
        except ValueError:
            _LOGGER.error("SlideSetPosition: '%s' has to be numeric", posin)
            return False

        if pos < 0 or pos > 1:
            _LOGGER.error("SlideSetPosition: '%s' has to be between 0.0-1.0",
                          pos)
            return False

        if not await self._checkauth():
            return False

        resp = await self._request('POST',
                                   'slide/{}/position'.format(slideid),
                                   {'pos': pos})
        return bool(resp)

    async def slideopen(self, slideid):
        """Open a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request('POST',
                                   'slide/{}/position'.format(slideid),
                                   {'pos': 0.0})
        return bool(resp)

    async def slideclose(self, slideid):
        """Close a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request('POST',
                                   'slide/{}/position'.format(slideid),
                                   {'pos': 1.0})
        return bool(resp)

    async def slidestop(self, slideid):
        """Stop a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request('POST',
                                   'slide/{}/stop'.format(slideid))
        return bool(resp)

    async def slidecalibrate(self, slideid):
        """Calibrate a slide."""
        if not await self._checkauth():
            return False

        resp = await self._request('POST',
                                   'slide/{}/calibrate'.format(slideid))
        return bool(resp)

    async def householdget(self):
        """Return household information."""
        if not await self._checkauth():
            return False

        resp = await self._request('GET', 'households')
        return resp

    async def householdset(self, name, address, lat, lon):
        """Set household information."""
        if not await self._checkauth():
            return False

        resp = await self._request('PATCH', 'households',
                                   {'name': name,
                                    'address': address,
                                    'lat': lat, 'lon': lon})
        return bool(resp)
