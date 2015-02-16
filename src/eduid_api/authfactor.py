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

import bson
import datetime

_VALID_FACTOR_TYPES = ['oath-hotp',
                       'oath-totp',
                       #'password',
                       #'U2F',
                       ]


class EduIDAuthFactor(object):
    """
    :param data: Factor type dependant parameters
    :param factor_type: Type identifier ('password', 'oath-totp', 'oath-hotp')

    :type data: dict
    :type factor_type: None | str | unicode
    """
    def __init__(self, data, factor_type=None):
        if not isinstance(data, dict):
            raise ValueError("Invalid 'data', not dict ({!r})".format(type(data)))
        if 'type' not in data:
            data['type'] = str(factor_type)
        self._data = {}
        self.type = data.pop('type')
        self.id = data.pop('id')
        self.created_by = data.pop('created_by')
        self.created_ts = data.pop('created_ts', None)

    @property
    def type(self):
        """
        :return: Credential type. Either 'oath-hotp' or 'oath-totp'.
        :rtype: str
        """
        return self._data['type']

    @type.setter
    def type(self, value):
        """
        :param value: Either 'oath-hotp' or 'oath-totp'.
        :type value: str
        """
        value = str(value)
        if value not in _VALID_FACTOR_TYPES:
            raise ValueError("Invalid 'type' value: {!r}".format(value))
        self._data['type'] = str(value)

    @property
    def id(self):
        """
        This is a reference to the credential in the authentication backend private database.

        :return: Unique ID of credential.
        :rtype: str
        """
        return self._data['id']

    @id.setter
    def id(self, value):
        """
        :param value: Unique ID of credential.
        :rtype: str
        """
        if isinstance(value, bson.ObjectId):
            value = str(value)
        if not isinstance(value, basestring):
            raise ValueError("Invalid 'id': {!r}".format(value))
        self._data['id'] = str(value)

    @property
    def created_by(self):
        """
        :return: Information about who created the credential.
        :rtype: str | unicode
        """
        return self._data.get('created_by')

    @created_by.setter
    def created_by(self, value):
        """
        :param value: Information about who created a credential.
        :type value: str | unicode
        """
        if self._data.get('created_by') is not None:
            # Once created_by is set, it should not be modified.
            raise ValueError("Refusing to modify created_by of credential")
        if not isinstance(value, basestring):
            raise ValueError("Invalid 'created_by' value: {!r}".format(value))
        self._data['created_by'] = str(value)

    @property
    def created_ts(self):
        """
        :return: Timestamp of credential creation.
        :rtype: datetime.datetime
        """
        return self._data.get('created_ts')

    @created_ts.setter
    def created_ts(self, value):
        """
        :param value: Timestamp of credential creation.
        :type value: None | datetime.datetime
        """
        if self._data.get('created_ts') is not None:
            # Once created_ts is set, it should not be modified.
            raise ValueError("Refusing to modify created_ts of credential")
        if value is None:
            value = datetime.datetime.utcnow()
        self._data['created_ts'] = value

    def to_dict(self):
        """
        Convert factor to a dict, that can be used to reconstruct the
        factor later.
        """
        return self._data


class EduIDAuthFactorOATH(EduIDAuthFactor):
    """
    OATH authentication factor.

    :param data: Factor type dependant parameters

    :type data: dict
    """
    def __init__(self, data):
        EduIDAuthFactor.__init__(self, data)

        if self.type not in ['oath-totp', 'oath-hotp']:
            raise ValueError("Invalid type in 'data': {!r}".format(self.type))

        if len(data) != 0:
            raise ValueError("Unknown elements in 'data: {!r}".format(data.keys()))


class EduIDAuthFactorPassword(EduIDAuthFactor):
    """
    Password authentication factor.

    :param data: Factor type dependant parameters

    :type data: dict
    """
    def __init__(self, data):
        # Disabled because untested
        raise NotImplemented('Password factors not implemented')

        EduIDAuthFactor.__init__(self, data)

        if self.type != 'password':
            raise ValueError("Invalid type in 'data': {!r}".format(self.type))

        self.salt = data.pop('salt')

        if len(data) != 0:
            raise ValueError("Unknown elements in 'data: {!r}".format(data.keys()))

    @property
    def salt(self):
        """
        :return: Password hashing parameters.
        :rtype: str | unicode
        """
        return self._data.get('salt')

    @salt.setter
    def salt(self, value):
        """
        :param value: Password hashing parameters.
        :type value: str | unicode
        """
        if self._data.get('salt') is not None:
            # Once salt is set, it should not be modified.
            raise ValueError("Refusing to modify salt of credential")
        if not isinstance(value, basestring):
            raise ValueError("Invalid 'salt' value: {!r}".format(value))
        self._data['salt'] = str(value)


def factor_from_dict(data, factor_type=None):
    """
    :param data: Factor type dependant parameters
    :param factor_type: Type identifier ('password', 'oath-totp', 'oath-hotp')

    :type data: dict
    :type factor_type: None | str | unicode
    """
    if not isinstance(data, dict):
        raise ValueError("Invalid 'data', not dict ({!r})".format(type(data)))
    if 'type' not in data:
        data['type'] = str(factor_type)
    if data['type'] in ['oath-totp', 'oath-hotp']:
        return EduIDAuthFactorOATH(data)
    elif data['type'] == 'password':
        return EduIDAuthFactorPassword(data)
    else:
        raise ValueError("Invalid 'factor_type' value: {!r}".format(data['type']))


class EduIDAuthFactorList(object):
    """
    Hold a list of authentication factors.
    """
    def __init__(self, factors):
        self.factors = []

        for this in factors:
            if isinstance(this, EduIDAuthFactor):
                factor = this
            else:
                factor = factor_from_dict(this)
            self.factors.append(factor)

    def to_list(self):
        """
        Return the list of factors as an iterable.
        :return: List of factors
        :rtype: [EduIDAuthFactor]
        """
        return self.factors

    def to_list_of_dicts(self):
        """
        Get the factors in a serialized format that can be stored in MongoDB.

        :return: List of dicts
        :rtype: [dict]
        """
        return [this.to_dict() for this in self.factors]
