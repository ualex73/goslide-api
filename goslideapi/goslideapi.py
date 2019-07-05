
import json
import logging
import asyncio
import aiohttp

_LOGGER = logging.getLogger(__name__)

BASEURL = 'https://api.goslide.io/api/{}'

class GoSlideCloud:
    """API Wrapper for the Go Slide devices"""

    def __init__(self, username, password):
        """Create the object with required parameters."""
        self._username = username
        self._password = password
        self._authenticated = False
        self._accesstoken = ''
        self._expiretoken = None
        self._authfailed = 0

    async def _dorequest(self, type, urlsuffix, data=None):
        """Internal request handler."""
        headers = {'Content-Type': 'application/json'}

        if self._authenticated:
            headers['Authorization'] = 'Bearer {}'.format(self._accesstoken)

        _LOGGER.debug('%s API: %s, data=%s', type, BASEURL.format(urlsuffix), json.dumps(data))

        async with aiohttp.request(type, BASEURL.format(urlsuffix), headers=headers, json=data) as resp:
            if resp.status == 200:
                textdata = await resp.text()
                _LOGGER.debug('REQUEST=%s, HTTPCode=200, Data=%s', BASEURL.format(urlsuffix), textdata)
                try:
                    jsondata = json.loads(textdata)
                except:
                    _LOGGER.error('Invalid JSON response "%s"', textdata)
                    jsondata = None
                    pass
                
                return jsondata
            else:
                textdata = await resp.text()
                _LOGGER.error('REQUEST=%s, HTTPCode=%s, Data=%s', BASEURL.format(urlsuffix), resp.status, textdata)

                if resp.status == 401:
                    self._authfailed += 1

                return None


    async def _request(self, *args):
        """Wrapper around dorequest to do at least 1 retry if we got a HTTP=401."""
        resp = await self._dorequest(*args)

        if self._authfailed > 0:
            _LOGGER.warning('Retrying request')
            resp = await self._dorequest(*args)
            if self._authfailed > 0:
                _LOGGER.error('Request failed')

        return resp


    async def _checkauth(self):
        """Check if we are authenticated and if we should refresh our token if it less valid then 7 days."""
        if self._authenticated:
            import datetime

            if self._expiretoken != None:
                if (self._expiretoken - datetime.datetime.now(datetime.timezone.utc)).days <= 7:
                    result = await self.login()
                    return result
            else:
                return True
        else:
            return await self.login()


    async def login(self):
        """Login to the Cloud API and retrieve a token."""
        import datetime

        self._authenticated = False
        self._accesstoken = ''

        result = await self._request('POST', 'auth/login', {'email': self._username, 'password': self._password})
        if result:
            if 'access_token' in result:
                self._authfailed = 0
                self._authenticated = True
                self._accesstoken = result['access_token']
                if 'expires_at' in result:
                    self._expiretoken = datetime.datetime.strptime(result['expires_at'] + ' +0000', '%Y-%m-%d %H:%M:%S %z')
                    _LOGGER.debug('Auth login token expiry: %s', result['expires_at'])
                else:
                    self._expiretoken = None
                    _LOGGER.error('Auth login JSON is missing the "expires_at" field in %s', result)

        return self._authenticated


    async def logout(self):
        """Logout of the Cloud API."""
        if self._authenticated:
            result = await self._request('POST', 'auth/logout')
            return True
        else:
            return False


    async def slidesoverview(self):
        """Retrieve the slides overview list. The format is:
           [{"device_name": "", "device_id": 1, "id": 1, "slide_setup": "", "curtain_type": "", "device_info": {"pos": 0.0}, "zone_id": "", "touch_go": ""}, {...}]
        """
        if self._checkauth:
            result = await self._request('GET', 'slides/overview')
            if result and 'slides' in result:
                return result['slides']
            else:
                _LOGGER.error('Missing key "slides" in JSON response "%s"', json.dumps(result))
                return None
        else:
            return None


    async def slidegetposition(self, slideid):
        """Retrieve the slide position. The format is:
           {"device_info": {"pos": 0.0}, "touch_go": ""}
        """
        if self._checkauth:
            result = await self._request('GET', 'slide/{}/info'.format(slideid))
            if result and 'device_info' in result and 'pos' in result['device_info']:
                        return result['device_info']['pos']
            else:
                #_LOGGER.error('Missing key "device_info" and "pos" in JSON response "%s"', json.dumps(result))
                return None
        else:
            return None


    async def slidesetposition(self, slideid, posin):
        """Set the slide position, only 0.0 - 1.0 is allowed."""
        try:
            pos = float(posin)
        except ValueError:
            _LOGGER.error('SlideSetPosition called, but "%s" is not numeric', posin)
            return None

        if pos < 0 or pos > 1:
            _LOGGER.error('SlideSetPosition called, but "%s" is not between 0.0 - 1.0', pos)
            return None

        if self._checkauth:
            result = await self._request('POST', 'slide/{}/position'.format(slideid), {'pos': pos})
        else:
            return None


    async def slideopen(self, slideid):
        """Open a slide."""
        if self._checkauth:
            result = await self._request('POST', 'slide/{}/position'.format(slideid), {'pos': 0.0})
        else:
            return None


    async def slideclose(self, slideid):
        """Close a slide."""
        if self._checkauth:
            result = await self._request('POST', 'slide/{}/position'.format(slideid), {'pos': 1.0})
        else:
            return None


    async def slidestop(self, slideid):
        """Stop a slide."""
        if self._checkauth:
            result = await self._request('POST', 'slide/{}/stop'.format(slideid))
        else:
            return None


    async def slidecalibrate(self, slideid):
        """Calibrate a slide."""
        if self._checkauth:
            result = await self._request('POST', 'slide/{}/calibrate'.format(slideid))
        else:
            return None


