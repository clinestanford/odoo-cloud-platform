# Copyright 2016-2019 Camptocamp SA
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html)

import json
import logging

import odoo.http
from odoo.http import SESSION_LIFETIME
from odoo.service import security
from odoo.tools._vendor.sessions import SessionStore

from . import json_encoding

DEFAULT_SESSION_TIMEOUT_ANONYMOUS = 60 * 60 * 3  # 3 hours in seconds

_logger = logging.getLogger(__name__)


class RedisSessionStore(SessionStore):
    """SessionStore that saves session to redis"""

    def __init__(
        self,
        redis,
        session_class=None,
        prefix="",
        expiration=None,
        anon_expiration=None,
    ):
        super().__init__(session_class=session_class)
        self.redis = redis
        if expiration is None:
            self.expiration = SESSION_LIFETIME
        else:
            self.expiration = expiration
        if anon_expiration is None:
            self.anon_expiration = DEFAULT_SESSION_TIMEOUT_ANONYMOUS
        else:
            self.anon_expiration = anon_expiration
        self.prefix = "session:"
        if prefix:
            self.prefix = f"{self.prefix}:{prefix}:"

    # Use the key generation and validation from FilesystemSessionStore
    # to produce keys long enough (84 chars) for the session rotation logic.
    generate_key = odoo.http.FilesystemSessionStore.generate_key
    is_valid_key = odoo.http.FilesystemSessionStore.is_valid_key

    def build_key(self, sid):
        return f"{self.prefix}{sid}"

    def save(self, session):
        key = self.build_key(session.sid)

        # Allow to set a custom expiration for a session
        # such as a very short one for monitoring requests.
        if session.uid:
            expiration = (
                session.get("expiration")
                or self.expiration
            )
        else:
            expiration = (
                session.get("expiration")
                or self.anon_expiration
            )
        if _logger.isEnabledFor(logging.DEBUG):
            if session.uid:
                user_msg = f"user '{session.login}' (id: {session.uid})"
            else:
                user_msg = "anonymous user"
            _logger.debug(
                "saving session with key '%s' and "
                "expiration of %s seconds for %s",
                key,
                expiration,
                user_msg,
            )

        data = json.dumps(dict(session), cls=json_encoding.SessionEncoder).encode(
            "utf-8"
        )
        if self.redis.set(key, data):
            if not (expiration and isinstance(expiration, int)):
                expiration = DEFAULT_SESSION_TIMEOUT_ANONYMOUS
            return self.redis.expire(key, expiration)

    def delete(self, session):
        key = self.build_key(session.sid)
        _logger.debug("deleting session with key %s", key)
        return self.redis.delete(key)

    def get(self, sid):
        if not self.is_valid_key(sid):
            _logger.debug(
                "session with invalid sid '%s' has been asked, "
                "returning a new one",
                sid,
            )
            return self.new()

        key = self.build_key(sid)
        saved = self.redis.get(key)
        if not saved:
            _logger.debug(
                "session with non-existent key '%s' has been asked, "
                "returning a new one",
                key,
            )
            return self.new()
        try:
            data = json.loads(saved.decode("utf-8"), cls=json_encoding.SessionDecoder)
        except ValueError:
            _logger.debug(
                "session for key '%s' has been asked but its json "
                "content could not be read, it has been reset",
                key,
            )
            data = {}
        return self.session_class(data, sid, False)

    def list(self):
        keys = self.redis.keys("%s*" % self.prefix)
        _logger.debug("a listing redis keys has been called")
        return [key[len(self.prefix) :] for key in keys]

    def rotate(self, session, env):
        """
        Rotate the session, matching the logic from Odoo 17.0's
        FilesystemSessionStore.rotate.
        """
        self.delete(session)
        session.sid = self.generate_key()
        if session.uid and env:
            session.session_token = security.compute_session_token(session, env)
        session.should_rotate = False
        self.save(session)

    def vacuum(self, *args, **kwargs):
        """Do not garbage collect the sessions.

        Redis keys are automatically cleaned at the end of their
        expiration.
        """
        return None