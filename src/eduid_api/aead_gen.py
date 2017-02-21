#
# Copyright (c) 2015 NORDUnet A/S
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
from eduid_api.aead import OATHAEAD_YHSM


class AEADGenRequest(BaseRequest):
    """
    A request to generate an AEAD.

    The AEAD will be returned, optionally together with it's plaintext (!).
    This is used to create OATH token credentials.

    Example AEAD generation request POSTed to /aead_gen:

        {
            "version":    1,
            "nonce":      "74b4a9a07084799548e5",
            "length":     20,
            "plaintext":  True
        }

    The 'nonce' has nothing to do with the AEADs nonce - it allows the API client to
    ensure that a response is in fact related to a specific request.

    :param request: JSON formatted request
    :param logger: logging object
    :type request: str
    :type logger: eduid_api.log.EduIDAPILogger
    """
    def __init__(self, request, remote_ip, logger):
        BaseRequest.__init__(self, request, remote_ip, 'aead_gen',
                             required = ['length'])

    @property
    def length(self):
        """
        AEAD length requested (in bytes).

        :rtype: int
        """
        return int(self._parsed_req['length'])

    @property
    def plaintext(self):
        """
        Client requests plaintext in response.

        :rtype: bool
        """
        return bool(self._parsed_req.get('plaintext', False))


def make_aead(req, logger, config):
    aead = OATHAEAD_YHSM(logger, config, num_bytes = req.length)
    res = {'status': 'OK',
           'aead': {'data': aead.aead,
                    'nonce': aead.nonce,
                    'key_handle': aead.keyhandle,
                    }}
    if req.plaintext:
        res['aead']['secret'] = aead.secret
    logger.debug("Creating {!r} response for {!r}".format(res['status'], req))
    return res
