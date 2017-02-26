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
import pkg_resources

from mock import patch
from werkzeug.exceptions import NotFound, Unauthorized

import eduid_common.authn
from eduid_common.api.testing import EduidAPITestCase
from eduid_api.app import init_eduid_api_app, EduIDAPIError

eduid_common.authn.TESTING = True


class FakeAEAD(object):
    def __init__(self, nonce, keyhandle, data):
        self.nonce = nonce
        self.keyhandle = keyhandle
        self.data = data


class FakeYubiHSM(object):

    def random(self, bytes):
        return 'B' * bytes

    def generate_aead_simple(self, nonce, keyhandle, data):
        return FakeAEAD(nonce, keyhandle, 'A' * len(data))


class AppTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        super(AppTests, self).setUp(create_user=False)
        self.client = self.app.test_client()
        self.priv_jwk = self.app.mystate.keys.private_key.jwk
        self.server_jwk = self.app.mystate.keys.lookup_by_name('self').jwk

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_eduid_api_app('testing', config)

    def update_config(self, config):
        config.update({
            'KEYSTORE_FN': os.path.join(self.datadir, 'test_keystore.json'),
            'VCCS_BASE_URL': 'dummy',
            })
        return config

    def tearDown(self):
        super(AppTests, self).tearDown()

    def request(self, url, request, remote_addr='127.0.0.1'):
        data = {}
        if request:
            data['request'] = request
        return self.client.post(url,
                                data = data,
                                environ_base = {'REMOTE_ADDR': remote_addr},
                                )

    def jose_request(self, url, claims, remote_addr='127.0.0.1', decode_response=True, add_standard = True):
        nonce_added = False
        if add_standard:
            if 'nonce' not in claims:
                claims['nonce'] = os.urandom(10).encode('hex')
                nonce_added = True
            if 'version' not in claims:
                claims['version'] = 1
        jwe = self._sign_and_encrypt(claims, self.priv_jwk, self.server_jwk)
        serialized = jose.serialize_compact(jwe)
        response = self.request(url, serialized, remote_addr = remote_addr)
        if not decode_response:
            return response
        jwt = self._decrypt_and_verify(response.data, self.priv_jwk, self.server_jwk)
        response_claims = jwt.claims
        self.app.logger.debug("Response claims:\n{!s}".format(pprint.pformat(response_claims)))
        if response_claims.get('nonce') != claims['nonce']:
            raise AssertionError('Response does not have the expected nonce ({!s} != {!s})'.format(
                response_claims.get('nonce'), claims.get('nonce'))
            )
        if nonce_added:
            response_claims.pop('nonce')
        return response_claims

    def _sign_and_encrypt(self, claims, priv_jwk, server_jwk, alg = 'RS256'):
        jws = jose.sign(claims, priv_jwk, alg=alg)
        signed_claims = {'v1': jose.serialize_compact(jws)}
        jwe = jose.encrypt(signed_claims, server_jwk)
        return jwe

    def _decrypt_and_verify(self, plaintext, decr_key, signing_key, alg = 'RS256'):
        jwe = jose.deserialize_compact(plaintext.replace("\n", ''))
        decrypted = jose.decrypt(jwe, decr_key)
        if 'v1' not in decrypted.claims:
            return False
        to_verify = jose.deserialize_compact(decrypted.claims['v1'])
        jwt = jose.verify(to_verify, signing_key, alg=alg)
        return jwt


class BaseAppTests(AppTests):

    def test_bad_request(self):
        """
        Verify bad requests are rejected
        """
        with self.assertRaises(NotFound):
            self.client.get('/')

    def test_unknown_client(self):
        """
        Test handling of unknown client.
        """
        with self.assertRaisesRegexp(EduIDAPIError, "Failed parsing request_str"):
            self.jose_request('/mfa_add', {}, remote_addr = '192.0.2.101',
                              decode_response = False, add_standard = False)

    def test_unknown_client_no_request(self):
        """
        Test handling of unknown client.
        """
        with self.assertRaises(Unauthorized):
            self.request('/mfa_add', None, remote_addr = '192.0.2.101')

    def test_ping(self):
        """
        Test the unprotected ping endpoint.
        """
        self.client.get('/ping') == ['pong']


def _mocked_requests_post(self, *args, **kwargs):
    """
    Mock the call to requests.post.
    We don't just return a static value, but rather call the real function
    that would have handled a request.
    """
    class MockedResponse(object):
        def __init__(self, text):
            self.text = text
    url = args[0]
    kwargs['environ_base'] = {'REMOTE_ADDR': '127.0.0.1'}
    response = self.client.post(url, **kwargs)
    res = MockedResponse(text = response.data)
    self.app.logger.debug('Mocked requests.post returning {!r}:\n{!s}'.format(res, res.text))
    return res


class AddRequestTests(AppTests):

    def test_mfa_add_request_without_HSM(self):
        """
        Test basic ability to parse an mfa_add request.
        """
        claims = {'token_type': 'OATH',
                  'OATH': {'digits': 6,
                           'issuer': 'TestIssuer',
                           'account': 'user@example.org',
                           }
                  }

        response_claims = self.jose_request('/mfa_add', claims)

        self.assertEqual(response_claims,
                         {u'reason': u'No local YubiHSM, and no OATH_AEAD_GEN_URL configured',
                          u'status': u'FAIL',
                          u'version': 1,
                          })

    def test_mfa_add_request(self):
        """
        Test using mfa_add to add a creedential using a local YubiHSM.
        """
        self.app.mystate.yhsm = FakeYubiHSM()
        self.app.mystate.oath_aead_keyhandle = 0x1234
        claims = {'token_type': 'OATH',
                  'OATH': {'digits': 6,
                           'issuer': 'TestIssuer',
                           'account': 'user@example.org',
                           }
                  }
        response_claims = self.jose_request('/mfa_add', claims)

        self.assertIn('OATH', response_claims)

        for this in ['hmac_key', 'key_uri', 'qr_png', 'user_id']:
            self.assertIn(this, response_claims['OATH'])

    @patch('requests.post')
    def test_mfa_add_request_remote(self, mocked_requests_post):
        """
        Test using mfa_add to add a creedential using a remote AEAD generating service.
        """
        def _call_mock(*x, **y):
            """
            Call the _mocked_requests_post function with a reference
            to 'self', after setting up a fake YubiHSM.

            This means that this test case starts up without an HSM,
            and fake actually calling another instance of this API
            that has an HSM connected to it (this is how the app is
            deployed currently).
            """
            _old_yhsm = self.app.mystate.yhsm
            self.app.mystate.yhsm = FakeYubiHSM()
            res = _mocked_requests_post(self, *x, **y)
            self.app.mystate.yhsm = _old_yhsm
            return res

        mocked_requests_post.side_effect = _call_mock
        self.app.mystate.oath_aead_keyhandle = 0x1234
        self.app.config['OATH_AEAD_GEN_URL'] = '/aead_gen'
        claims = {'token_type': 'OATH',
                  'OATH': {'digits': 6,
                           'issuer': 'TestIssuer',
                           'account': 'user@example.org',
                           }
                  }
        response_claims = self.jose_request('/mfa_add', claims)

        self.assertIn('OATH', response_claims)

        for this in ['hmac_key', 'key_uri', 'qr_png', 'user_id']:
            self.assertIn(this, response_claims['OATH'])

    def test_mfa_add_request_missing_params(self):
        """
        Test add_request with missing mandatory parameters.
        """
        claims = {'token_type': 'OATH',
                  }
        with self.assertRaises(EduIDAPIError) as cm:
            self.jose_request('/mfa_add', claims, decode_response = False)
            self.assertEqual(cm.exception.msg, "No 'nonce' in request_str")

        with self.assertRaises(EduIDAPIError) as cm:
            self.jose_request('/mfa_add', claims, decode_response = False)
            self.assertEqual(cm.exception.msg, "No 'OATH' in request_str")

        claims['OATH'] = {'digits': 6,
                          'issuer': 'TestIssuer',
                          'account': 'user@example.org',
                          }
        response_claims = self.jose_request('/mfa_add', claims)

        self.assertEqual(response_claims['status'], 'FAIL')
        self.assertEqual(response_claims['reason'], 'No local YubiHSM, and no OATH_AEAD_GEN_URL configured')


class MFATestTests(AppTests):

    def test_mfa_test(self):
        """
        Test basic ability to parse an mfa_test request.
        """
        claims = {}
        response_claims = self.jose_request('/mfa_test', claims)

        self.assertEqual(response_claims,
                         {u'mfa_test_status': u'OK',
                          })

    def test_mfa_test_not_an_allowed_command(self):
        """
        Test that a key without the mfa_test command can't invoke it.
        """
        claims = {}
        with self.assertRaisesRegexp(EduIDAPIError, "Method 'mfa_test' not allowed with key"):
            self.jose_request('/mfa_test', claims, remote_addr='127.0.0.2', decode_response = False)


class AuthRequestTests(AppTests):

    def test_mfa_auth_missing_code(self):
        """
        Test basic ability to parse an mfa_auth request.
        """
        claims = {'token_type': 'OATH',
                  'OATH': {'user_id': 'foo',
                           }
                  }
        with self.assertRaises(EduIDAPIError) as cm:
            self.jose_request('/mfa_auth', claims, decode_response = False)
            self.assertEqual(cm.exception.msg, "No 'user_code' in 'OATH' part of request")

    def test_mfa_auth_unknown_user(self):
        """
        Test authentication with unknown user.
        """
        claims = {'token_type': 'OATH',
                  'OATH': {'user_id': 'foo',
                           'user_code': '123456',
                           }
                  }
        response_claims = self.jose_request('/mfa_auth', claims)

        self.assertEqual(response_claims,
                         {u'reason': u'Unknown user',
                          u'status': u'FAIL',
                          u'version': 1,
                          })

    def test_mfa_auth(self):
        """
        Test basic ability to parse an mfa_add request.
        """

        # First, add a new credential
        self.app.mystate.yhsm = FakeYubiHSM()
        self.app.mystate.oath_aead_keyhandle = 0x1234
        claims = {'token_type': 'OATH',
                  'OATH': {'digits': 6,
                           'issuer': 'TestIssuer',
                           'account': 'user@example.org',
                           }
                  }
        response_claims = self.jose_request('/mfa_add', claims)

        self.assertIn('OATH', response_claims)

        for this in ['hmac_key', 'key_uri', 'qr_png', 'user_id']:
            self.assertIn(this, response_claims['OATH'])

        user_id = response_claims['OATH']['user_id']

        #
        # Now, test authentication with that credential
        #
        claims = {'token_type': 'OATH',
                  'OATH': {'user_id': user_id,
                           'user_code': '123456',
                           }
                  }
        response_claims = self.jose_request('/mfa_auth', claims)

        self.assertEqual(response_claims,
                         {u'status': u'OK',
                          u'OATH': {u'authenticated': True},
                          })


class AeadGenRequestTests(AppTests):

    def test_aead_gen_incomplete(self):
        """
        Test basic ability to parse an aead_gen request.
        """
        claims = {}
        with self.assertRaisesRegexp(EduIDAPIError, "No 'length' in request_str"):
            self.jose_request('/aead_gen', claims, decode_response = False)

    def test_aead_gen(self):
        """
        Test basic ability to parse an aead_gen request.
        """
        self.app.mystate.yhsm = FakeYubiHSM()
        self.app.mystate.oath_aead_keyhandle = 0x1234
        claims = {'length': 10,
                  }
        response_claims = self.jose_request('/aead_gen', claims)

        self.assertEqual(response_claims,
                         {u'status': u'OK',
                          u'aead': {u'data': u'4141414141414141414141414141',
                                    u'key_handle': self.app.mystate.oath_aead_keyhandle,
                                    u'nonce': u'00'},
                          })

    def test_aead_gen_with_plaintext(self):
        """
        Test basic ability to parse an aead_gen request.
        """
        self.app.mystate.yhsm = FakeYubiHSM()
        self.app.mystate.oath_aead_keyhandle = 0x1234
        claims = {'length': 10,
                  'plaintext': True,
                  }
        response_claims = self.jose_request('/aead_gen', claims)

        decoded_secret = response_claims['aead'].pop('secret').decode('hex')
        self.assertEqual(len(decoded_secret), claims['length'])
        self.assertEqual(response_claims,
                         {u'status': u'OK',
                          u'aead': {u'data': u'4141414141414141414141414141',
                                    u'key_handle': self.app.mystate.oath_aead_keyhandle,
                                    u'nonce': u'00'},
                          })
