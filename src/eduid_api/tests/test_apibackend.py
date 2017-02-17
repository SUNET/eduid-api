#!/usr/bin/python
#
# Copyright (c) 2013 NORDUnet A/S
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

"""
Test the eduID API backend.
"""

import os
import jose
import pprint
import unittest
import pkg_resources

import simplejson as json

from eduid_common.api.testing import EduidAPITestCase
from eduid_api.app import init_eduid_api_app

from werkzeug.exceptions import NotFound


class AppTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        super(AppTests, self).setUp(create_user=False)
        self.client = self.app.test_client()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_eduid_api_app('testing', config)

    def update_config(self, config):
        config.update({
            'KEYSTORE_FN': os.path.join(self.datadir, 'test_keystore.json'),
            })
        return config

    def tearDown(self):
        super(AppTests, self).tearDown()

    def request(self, url, request):
        return self.client.post(url,
                                data = {'request': request},
                                environ_base = {'REMOTE_ADDR': '127.0.0.1'},
                                )

    def _sign_and_encrypt(self, claims, priv_jwk, server_jwk, alg = 'RS256'):
        jws = jose.sign(claims, priv_jwk, alg=alg)
        signed_claims = {'v1': jose.serialize_compact(jws)}
        jwe = jose.encrypt(signed_claims, server_jwk)
        return jwe


    def _decrypt_and_verify(self, plaintext, decr_key, signing_key, alg = 'RS256'):
        jwe = jose.deserialize_compact(plaintext.replace("\n", ''))
        decrypted = jose.decrypt(jwe, decr_key)
        if not 'v1' in decrypted.claims:
            return False
        to_verify = jose.deserialize_compact(decrypted.claims['v1'])
        jwt = jose.verify(to_verify, signing_key, alg=alg)
        return jwt

    def test_bad_request(self):
        """
        Verify bad requests are rejected
        """
        #raise unittest.SkipTest("test disabled because add_raw has been removed")

        with self.assertRaises(NotFound):
            self.client.get('/')

    def test_mfa_add_request(self):
        """
        Test basic ability to parse an mfa_add request.

        :return:
        """
        nonce = os.urandom(10)
        claims = {'version': 1,
                  'token_type': 'OATH',
                  'nonce': nonce.encode('hex'),
                  'OATH': {'digits': 6,
                           'issuer': 'TestIssuer',
                           'account': 'user@example.org',
                           }
                  }
        priv_jwk = self.app.mystate.keys.private_key.jwk
        server_jwk = self.app.mystate.keys.lookup_by_name('self').jwk
        jwe = self._sign_and_encrypt(claims, priv_jwk, server_jwk)
        serialized = jose.serialize_compact(jwe)

        response = self.request('/mfa_add', serialized)

        jwt = self._decrypt_and_verify(response.data, priv_jwk, server_jwk)

        response_claims = jwt.claims

        self.app.logger.debug("Response claims:\n{!s}".format(pprint.pformat(response_claims)))

        self.assertEqual(response_claims,
                         {u'nonce': nonce.encode('hex'),
                          u'reason': u'No local YubiHSM, and no OATH_AEAD_GEN_URL configured',
                          u'status': u'FAIL',
                          u'version': 1,
                          })
