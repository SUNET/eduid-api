#
# Copyright (c) 2017 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

from eduid_api.request import BaseRequest
from eduid_api.common import EduIDAPIError


class MFATestRequest(BaseRequest):
    """
    Base request to test communication with the API.

    Example request POSTed to /mfa_test:

        {
            "version":    1,
            "nonce":      "3607c28b22abc12ae8b4",
        }


    :param request: JSON formatted request
    :param logger: logging object

    :type request: str
    :type logger: eduid_api.log.EduIDAPILogger
    """
    def __init__(self, request, remote_ip, logger):
        BaseRequest.__init__(self, request, remote_ip, 'mfa_auth')

        for req_field in ['nonce', 'version']:
            if req_field not in self._parsed_req:
                raise EduIDAPIError('No {!r} in request'.format(req_field))

        ver = self._parsed_req['version']
        if int(ver) != 1:
            raise EduIDAPIError('Unknown version in request: {!r}'.format(ver))


class TestAction(object):
    """
    Perform light self-test.

    :param request: Request object

    :type request: MFAAuthRequest
    :type logger: logging.logger
    """
    def __init__(self, request, logger):
        self._request = request
        self._logger = logger
        self._status = 'OK'

    def response(self):
        """
        Create a response dict to be returned (JSON formatted) to the API client.

        :return: Response
        :rtype: dict
        """
        res = {'mfa_test_status': self._status}
        self._logger.debug('Creating {!r} response for {!r}'.format(self._status, self._request))
        res['nonce'] = self._request.nonce  # Copy nonce (request id) from request to response
        return res


def test(req, logger):
    """
    Add a new token to the API auth system.

    :param req: The parsed test-request
    :param logger: Logger

    :type req: MFAAuthRequest
    :type logger: logging.logger

    :return: Resppnse dict
    :rtype: dict
    """
    return TestAction(req, logger).response()
