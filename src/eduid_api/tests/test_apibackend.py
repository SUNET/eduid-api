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

import cherrypy
import cptestcase
import simplejson as json

import eduid_api
from eduid_api.eduid_apibackend import APIBackend
from eduid_api.keystore import APIKey


class TestAuthBackend(cptestcase.BaseCherryPyTestCase):

    def setUp(self):
        debug = True
        self.datadir = pkg_resources.resource_filename(__name__, 'data')
        self.config_file = os.path.join(self.datadir, 'test_config.ini')
        self.config = eduid_api.config.EduIDAPIConfig(self.config_file, debug)
        self.logger = eduid_api.log.EduIDAPILogger('test_apibackend', self.config)
        try:
            self.db = eduid_api.db.EduIDAPIDB(self.config.mongodb_uri)
            self.authstore = eduid_api.authstore.APIAuthStoreMongoDB(self.config.mongodb_uri, self.logger)
        except Exception:
            # will skip tests that require mongodb
            self.db = None
            self.authstore = None

        # load example certificate and key
        _keystore_data = {"self": {"JWK": {"file": os.path.join(self.datadir, 'example.pem')},
                                   "ip_addresses": ["127.0.0.1",
                                                    ],
                                   "allowed_commands": ["mfa_add"],
                                   "owner": "example.org"
        },

                          "_private": {"JWK": {"file": os.path.join(self.datadir, 'example.key')},
                                       "ip_addresses": []
                          }
        }
        self.config.keys._keys = [APIKey(name, value) for (name, value) in _keystore_data.items()]

        self.apibackend = APIBackend(self.logger, self.db, self.authstore, self.config, expose_real_errors=True)

        cherrypy.tree.mount(self.apibackend, '/')
        cherrypy.engine.start()

    def tearDown(self):
        cherrypy.engine.exit()

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

        response = self.request('/', return_error=True)
        self.assertEqual(response.output_status, '500 Internal Server Error')
        self.assertIn('404 Not Found', response.body[0])

    def test_add_raw_request_wrong_version(self):
        """
        Verify add_raw request with wrong version is rejected
        """
        raise unittest.SkipTest("test disabled because add_raw has been removed")

        a = {'add_raw': {},
             'version': 9999,
             }
        j = json.dumps(a)
        response = self.request('/add_raw', request=j, return_error=True)
        self.assertIn('Unknown request version : 9999', response.body[0])

        # try again with blinding
        self.apibackend.expose_real_errors = False
        response = self.request('/add_raw', request=j, return_error=True)
        self.assertEqual(response.output_status, '500 Internal Server Error')

    def test_add_raw_missing_data(self):
        """
        Verify add_raw request with missing data is rejected
        """
        raise unittest.SkipTest("test disabled because add_raw has been removed")

        for req_field in ['data']:
            a = {'add_raw': {'foo': 'bar'},
                 'version': 1,
                 }
            if req_field in a['add_raw']:
                del a['add_raw'][req_field]
            j = json.dumps(a)
            response = self.request('/add_raw', request=j, return_error=True)
            self.assertIn("No '{!s}' in request".format(req_field), response.body[0])

    def test_add_raw_request1(self):
        """
        Verify correct add_raw request
        """
        if self.db is None:
            raise unittest.SkipTest("requires accessible MongoDB server on {!s}".format(
                    self.config.mongodb_uri))

        raise unittest.SkipTest("test disabled because AMQP server can't be mocked at this time")

        a = {'add_raw':
                 {'data': {'email': 'ft@example.net',
                           'verified': True,
                           },
                  },
             'version': 1,
             }
        j = json.dumps(a)
        response = self.request('/add_raw', request=j, return_error=True)
        res = json.loads(response.body[0])
        expected = {'add_raw':
                        {'version': 1,
                         'success': True,
                         }
                    }
        self.assertEqual(res, expected)

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
        priv_jwk = self.config.keys.private_key.jwk
        server_jwk = self.config.keys.lookup_by_name("self").jwk
        jwe = self._sign_and_encrypt(claims, priv_jwk, server_jwk)
        serialized = jose.serialize_compact(jwe)

        response = self.request('/mfa_add', request=serialized, return_error=True)

        jwt = self._decrypt_and_verify(response.body[0], priv_jwk, server_jwk)

        response_claims = jwt.claims

        self.logger.debug("Response claims:\n{!s}".format(pprint.pformat(response_claims)))

        self.assertEqual(response_claims,
                         {u'nonce': nonce.encode('hex'),
                          u'reason': u'No API Key found for OATH AEAD service',
                          u'status': u'FAIL',
                          u'version': 1,
                          })
