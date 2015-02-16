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

"""
Authentication user data objects.
"""

from eduid_api.authfactor import EduIDAuthFactorList

from eduid_api.common import APIAuthenticationError

_VALID_STATUS_VALUES = ['enabled', 'disabled']


class APIAuthUserError(APIAuthenticationError):
    """
    Error regarding APIAuthUser instances.
    """
    pass


class APIAuthUser(object):
    """
    Represents the data kept in the eduid-API private authstore.

    Example data for a user:

        {
            "_id" : ObjectId("54cf8ee38a5da5000e0e2948"),
            "revision" : 1,
            "authuser" : {
                    "status" : "enabled",
                    "owner" : "example.edu",
                    "factors" : [
                            {
                                    "created_ts" : ISODate("2015-02-02T14:51:15.005Z"),
                                    "type" : "oath-totp",
                                    "id" : "54cf8ee28a5da5000e0e2947",
                                    "created_by" : "eduid-api"
                            }
                    ]
            }
        }

    The 'revision' is to provide atomic updates of the actual content which is below 'authuser'.
    """
    def __init__(self, data, metadata, check_enabled):
        self._data = data
        self._metadata = metadata
        # validate known data
        self.status = data['status']
        self.owner = data.get('owner')
        self._factors = EduIDAuthFactorList(data['factors'])

        if check_enabled and self.status != 'enabled':
            raise APIAuthUserError("Disabled authuser requested")

    @property
    def user_id(self):
        """
        :return: Unique id of authuser.
        :rtype: str | None
        """
        return self._data.get('user_id')

    @user_id.setter
    def user_id(self, value):
        """
        :param value: Either a bson.objectId or a string.
        :type value: str | unicode | bson.objectId
        """
        self._data['user_id'] = str(value)

    @property
    def status(self):
        """
        :return: Status of authuser. Either 'enabled' or 'disabled'.
        :rtype: str
        """
        return self._data['status']

    @status.setter
    def status(self, value):
        """
        :param value: Either 'enabled' or 'disabled'.
        :type value: str | unicode
        """
        if value not in _VALID_STATUS_VALUES:
            raise ValueError("Invalid 'status' value: {!r}".format(value))
        self._data['status'] = str(value)

    @property
    def owner(self):
        """
        :return: Owner of authuser.
        :rtype: str
        """
        return self._data['owner']

    @owner.setter
    def owner(self, value):
        """
        :param value: Owner's name from APIKey.owner
        :type value: str | unicode
        """
        self._data['owner'] = str(value)

    @property
    def factors(self):
        """
        :return: Factors associated with authuser.
        :rtype: eduid_api.authfactor.EduIDAuthFactorList
        """
        return self._factors

    @property
    def metadata(self):
        """
        :return: Opaque data about this authuser. This data is owned by APIAuthStore.
        """
        return self._metadata

    def to_dict(self):
        """
        Convert authuser to a dict, that can be used to reconstruct the
        authuser later.
        """
        self._data['factors'] = self.factors.to_list_of_dicts()
        return self._data


def from_dict(data, metadata = None, check_enabled=True):
    """
    Create a suitable APIAuthUser object based on the 'type' of 'data'.

    :param data: dict with authuser data - probably from a database
    :param metadata: opaque data about this authuser (default: {})
    :param check_enabled: boolean controlling check of authuser status after creation

    :type data: dict
    :type check_enabled: bool
    :rtype: APIAuthUser
    """
    if not metadata:
        metadata = {}
    return APIAuthUser(data, metadata, check_enabled)
