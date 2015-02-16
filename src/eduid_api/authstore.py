#
# Copyright (c) 2013, 2015 NORDUnet A/S
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
Store APIAuthUser objects in database.

This file was copied from the VCCS project.
"""

import pymongo
import bson
import time

import eduid_api.authuser
from eduid_api.authuser import APIAuthUser


class APIAuthStore():

    """
    Class providing access to the eduid-API private credential store.
    """

    def __init__(self):
        pass

    def get_authuser(self, user_id, check_active=True):
        """
        Get a credential from the database.

        Unless check_active is False, it will be verified that this is not a
        revoked credential.

        :param user_id: unique identifier as string
        :param check_active: If True, do not return revoked credentials

        :type user_id: str
        :type check_active: bool
        :rtype: APIAuthUser
        """
        raise NotImplementedError("Subclass should implement get_credential")

    def add_authuser(self, user):
        """
        Add a new credential to the database.

        :type user: APIAuthUser
        :returns: True on success
        """
        raise NotImplementedError("Subclass should implement add_credential")

    def update_authuser(self, user, safe=True):
        """
        Update an existing credential in the database.

        :type user: APIAuthUser
        :param safe: boolean, sub-class specific meaning
        :returns: True on success
        """
        raise NotImplementedError("Subclass should implement update_credential")


class APIAuthStoreMongoDB(APIAuthStore):
    """
    Store APIAuthUser objects in MongoDB.

    The MongoDB documents look like this :

    {'_id': mongodb's unique id,
     'revision': integer - used to do atomic updates,
     'authuser': dict that can be turned into APIAuthUser,
     }
    """

    def __init__(self, uri, logger, conn=None, db_name="eduid_api", retries=10, **kwargs):
        APIAuthStore.__init__(self)
        self._logger = logger
        if conn is not None:
            self.connection = conn
        else:
            if "replicaSet=" in uri:
                self.connection = pymongo.MongoReplicaSetClient(uri, **kwargs)
            else:
                self.connection = pymongo.MongoClient(uri, **kwargs)
        self.db = self.connection[db_name]
        self.coll = self.db['authusers']
        for this in xrange(retries):
            try:
                self.coll.ensure_index([('authuser.factors.id', 1)], name='factor_id_idx', unique=True)
                break
            except (pymongo.errors.AutoReconnect, bson.errors.InvalidDocument) as exc:
                # InvalidDocument: When eduid-API starts at the same time as MongoDB (e.g. on reboot),
                # this error can be returned while MongoDB sorts out it's replica set status.
                if this == (retries - 1):
                    logger.error("Failed ensuring mongodb index, giving up after {!r} retries.".format(retries))
                    raise
                logger.debug("Failed ensuring mongodb index, retrying ({!r})".format(exc))
            time.sleep(1)

    def get_authuser(self, user_id, check_revoked=True):
        """
        Retrieve a user from the database based on it's user_id (not _id).

        The user_id is a string supplied to the authentication backends
        from the frontend servers.

        :param user_id: string
        :param check_revoked: boolean - True to raise exception on revoked credentials

        :type user_id: str
        :type check_revoked: bool
        :rtype: APIAuthUser
        """
        if not isinstance(user_id, basestring):
            raise TypeError("non-string user_id")
        self._logger.debug("Get authuser {!r}".format(user_id))
        query = {'authuser.user_id': str(user_id)}
        res = self.coll.find_one(query)
        if res is None:
            return None
        metadata = {'id': res['_id'],
                    'revision': res['revision'],
                    }
        cred = eduid_api.authuser.from_dict(res['authuser'],
                                            metadata = metadata,
                                            check_enabled = check_revoked,
                                            )
        return cred

    def add_authuser(self, user):
        """
        Add a new user to the MongoDB collection.

        :type user: APIAuthUser
        :returns: True on success, False or result of MongoDB insert()
        """
        if not isinstance(user, APIAuthUser):
            raise TypeError("non-APIAuthUser cred")
        if not user.user_id:
            user.user_id = bson.ObjectId()
        docu = {'revision': 1,
                'authuser': user.to_dict(),
                }
        self._logger.debug("Add authuser:\n{!r}".format(docu))
        try:
            res = self.coll.insert(docu)
            return res
        except pymongo.errors.DuplicateKeyError:
            return False

    def update_authuser(self, user, safe=True):
        """
        Update an existing user in the MongoDB collection.

        Ensures atomic update using an increasing 'revision' attribute.

        :type user: APIAuthUser
        :param safe: If True, block until write operation has completed
        :returns: True on success, False or result of MongoDB update()
        """
        if not isinstance(user, APIAuthUser):
            raise TypeError("non-APIAuthUser cred")
        metadata = user.metadata
        spec = {'_id': metadata['id'],
                'revision': metadata['revision'],
                }
        data = {'revision': metadata['revision'] + 1,
                'authuser': user.to_dict(),
                }
        self._logger.debug("Update authuser:\n{!r}".format(data))
        # XXX this function should return True on success
        return self.coll.update(spec, {'$set': data}, safe=safe)
