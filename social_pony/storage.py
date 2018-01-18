"""SQLAlchemy models for Social Auth"""
import base64
import six
import json

try:
    import transaction
except ImportError:
    transaction = None

from pony.orm import *
# from sqlalchemy import Column, Integer, String
# from sqlalchemy.exc import IntegrityError
# from sqlalchemy.types import PickleType, Text
# from sqlalchemy.schema import UniqueConstraint
# from sqlalchemy.ext.declarative import declared_attr
# from sqlalchemy.ext.mutable import MutableDict

from social_core.storage import UserMixin, AssociationMixin, NonceMixin, \
                                CodeMixin, PartialMixin, BaseStorage


def get_query_by_dict_param(cls, **params):
    query = ' and '.join(['x.%s == %s' % (k, json.dumps(v)) for k, v in params.items()])
    return cls.select(eval('lambda x: %s' % query))


class PonyMixin(object):
    COMMIT_SESSION = True

    @classmethod
    def _session(cls):
        return None

    @classmethod
    def _query(cls):
        return cls

    @classmethod
    def _new_instance(cls, model, *args, **kwargs):
        return cls._save_instance(
            model(*args, **kwargs)
        )

    @classmethod
    def _save_instance(cls, instance):
        if cls.COMMIT_SESSION:
            commit()
        else:
            flush()
        return instance

    @classmethod
    def _flush(cls):
        flush()

    def save(self):
        self._save_instance(self)


class PonyUserMixin(PonyMixin, UserMixin):
    """Social Auth association model"""
    _table_ = 'social_auth_usersocialauth'
    composite_index('provider', 'uid')

    provider = Required(str, 32)
    extra_data = Optional(LongStr)

    uid = None
    user_id = None
    user = None

    @classmethod
    def changed(cls, user):
        cls._save_instance(user)

    def set_extra_data(self, extra_data=None):
        if not extra_data: return
        if super(PonyUserMixin, self).set_extra_data(json.dumps(extra_data)):
            self._save_instance(self)

    @classmethod
    def allowed_to_disconnect(cls, user, backend_name, association_id=None):
        if association_id is not None:
            qs = cls.select(lambda x: x.id != association_id)
        else:
            qs = cls.select(lambda x: x.provider != backend_name)

        qs = qs.filter(lambda x: x.user == user)

        if hasattr(user, 'has_usable_password'):  # TODO
            valid_password = user.has_usable_password()
        else:
            valid_password = True
        return valid_password or qs.count() > 0

    @classmethod
    def disconnect(cls, entry):
        entry.delete()

    @classmethod
    def user_exists(cls, *args, **kwargs):
        """
        Return True/False if a User instance exists with the given arguments.
        Arguments are directly passed to filter() manager method.
        """
        print('args: ', args)
        return get_query_by_dict_param(cls.user_model(), **kwargs).count() > 0

    @classmethod
    def get_username(cls, user):
        return getattr(user, 'username', None)

    @classmethod
    def create_user(cls, *args, **kwargs):
        print('args: ', args)
        return cls.user_model()(**kwargs)

    @classmethod
    def get_user(cls, pk):
        return cls.user_model().get(lambda x: x.id == pk)

    @classmethod
    def get_users_by_email(cls, email):
        return cls.user_model().select(lambda x: x.email == email)

    @classmethod
    def get_social_auth(cls, provider, uid):
        if not isinstance(uid, six.string_types):
            uid = str(uid)
        try:
            return cls.select(lambda x: x.provider == provider and x.uid == uid)[:][0]
        except IndexError:
            return None

    @classmethod
    def get_social_auth_for_user(cls, user, provider=None, id=None):
        qs = cls.select(lambda x: x.user_id == user.id)
        if provider:
            qs = qs.filter(lambda x: x.provider == provider)
        if id:
            qs = qs.filter(lambda x: x.id == id)
        return qs

    @classmethod
    def create_social_auth(cls, user, uid, provider):
        if not isinstance(uid, six.string_types):
            uid = str(uid)
        return cls(
            user=user,
            uid=uid,
            provider=provider
        )


class PonyNonceMixin(PonyMixin, NonceMixin):
    _table_ = 'social_auth_nonce'
    composite_index('server_url', 'timestamp', 'salt')

    server_url = Required(str, 255)
    timestamp = Required(int)
    salt = Required(str, 40)

    @classmethod
    def use(cls, server_url, timestamp, salt):
        kwargs = {
            'server_url': server_url,
            'timestamp': timestamp,
            'salt': salt
        }
        try:
            return get_query_by_dict_param(cls, **kwargs)[:][0]
        except IndexError:
            return cls(**kwargs)


class PonyAssociationMixin(PonyMixin, AssociationMixin):
    _table_ = 'social_auth_association'
    composite_index('server_url', 'handle')

    server_url = Required(str, 255)
    handle = Required(str, 255)
    secret = Required(str, 255)  # base64 encoded
    issued = Required(int)
    lifetime = Required(int)
    assoc_type = Required(str, 64)

    @classmethod
    def store(cls, server_url, association):
        # Don't use get_or_create because issued cannot be null
        try:
            assoc = cls.select(lambda x: x.server_url == server_url and \
                                           x.handle == association.handle)[:][0]
        except IndexError:
            assoc = cls(server_url=server_url,
                        handle=association.handle)
        assoc.secret = base64.encodestring(association.secret).decode()
        assoc.issued = association.issued
        assoc.lifetime = association.lifetime
        assoc.assoc_type = association.assoc_type
        cls._save_instance(assoc)

    @classmethod
    def get(cls, *args, **kwargs):
        print('args: ', args)
        return get_query_by_dict_param(cls, **kwargs)

    @classmethod
    def remove(cls, ids_to_delete):
        cls.select(lambda x: x in ids_to_delete).delete()


class PonyCodeMixin(PonyMixin, CodeMixin):
    _table_ = 'social_auth_code'
    composite_index('code', 'email')

    email = Required(str, 200)
    code = Required(str, 32, index=True)

    @classmethod
    def get_code(cls, code):
        return cls.select(lambda x: x.code == code)[:][0]


class PonyPartialMixin(PonyMixin, PartialMixin):
    _table_ = 'social_auth_partial'

    token = Required(str, 32, index=True)
    data = Required(Json)
    next_step = Required(str)
    backend = Required(str, 32)

    @classmethod
    def load(cls, token):
        return cls.select(lambda x: x.token == token)[:][0]

    @classmethod
    def destroy(cls, token):
        partial = cls.load(token)
        if partial:
            partial.delete()


class BasePonyStorage(BaseStorage):
    user = PonyUserMixin
    nonce = PonyNonceMixin
    association = PonyAssociationMixin
    code = PonyCodeMixin
    partial = PonyPartialMixin

    @classmethod
    def is_integrity_error(cls, exception):
        return exception.__class__ is IntegrityError
