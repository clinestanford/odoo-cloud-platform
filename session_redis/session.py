# Copyright 2016-2019 Camptocamp SA
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html)

import json
import logging
import time

import odoo.http
from odoo.http import SESSION_DELETION_TIMER, STORED_SESSION_BYTES
from odoo.service import security
from odoo.tools._vendor.sessions import SessionStore

from . import json_encoding

# this is equal to the duration of the session garbage collector in
# odoo.http.session_gc()
DEFAULT_SESSION_TIMEOUT = 60 * 60 * 24 * 7  # 7 days in seconds
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
            self.expiration = DEFAULT_SESSION_TIMEOUT
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

        # If the session has a deletion_time, it is slated for rotation,
        # and should be removed once the rotation window is over.
        # Otherwise, allow to set a custom expiration for a session
        # such as a very short one for monitoring requests.
        if session.uid:
            expiration = (
                session.get("deletion_time")
                or session.get("expiration")
                or self.expiration
            )
        else:
            expiration = (
                session.get("deletion_time")
                or session.get("expiration")
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

    def rotate(self, session, env, soft=False):
        """
        Rotate the session, matching the logic from Odoo's
        FilesystemSessionStore.rotate for proper soft/hard rotation support.
        """
        if soft:
            # Soft rotation: keep the first STORED_SESSION_BYTES of the sid
            # so that things like CSRF tokens and device tracking still work.
            static = session.sid[:STORED_SESSION_BYTES]
            recent_session = self.get(session.sid)
            if "next_sid" in recent_session:
                # A concurrent request already rotated this session.
                session.sid = recent_session["next_sid"]
                return
            next_sid = static + self.generate_key()[STORED_SESSION_BYTES:]
            session["next_sid"] = next_sid
            session["deletion_time"] = time.time() + SESSION_DELETION_TIMER
            self.save(session)
            # Now prepare the new session
            session["gc_previous_sessions"] = True
            session.sid = next_sid
            del session["deletion_time"]
            del session["next_sid"]
        else:
            # Hard rotation: completely new sid (e.g. after logout or
            # password/API key change).
            self.delete(session)
            session.sid = self.generate_key()
        if session.uid:
            assert env, "saving this session requires an environment"
            session.session_token = security.compute_session_token(session, env)
        session.should_rotate = False
        session["create_time"] = time.time()
        self.save(session)

    def delete_old_sessions(self, session):
        """
        Cleanup rotated sessions after the deletion timer has expired.
        Mirrors FilesystemSessionStore.delete_old_sessions.
        """
        if "gc_previous_sessions" in session:
            if session["create_time"] + SESSION_DELETION_TIMER < time.time():
                self.delete_from_identifiers([session.sid[:STORED_SESSION_BYTES]])
                del session["gc_previous_sessions"]
                self.save(session)

    def delete_from_identifiers(self, identifiers):
        """
        Given a list of partial session ids (identifiers), remove any
        matching sessions from Redis. Used by device revocation and
        session rotation cleanup.
        """
        patterns_to_unlink = []
        for identifier in identifiers:
            if not odoo.http._session_identifier_re.match(identifier):
                raise ValueError(
                    "Identifier format incorrect, did you pass in a string "
                    "instead of a list?"
                )
            patterns_to_unlink.append(f"{self.prefix}{identifier}*")
        keys_to_unlink = []
        for pattern in patterns_to_unlink:
            keys_to_unlink.extend(self.redis.scan_iter(match=pattern))
        if keys_to_unlink:
            self.redis.delete(*keys_to_unlink)

    def get_missing_session_identifiers(self, identifiers):
        """
        Given a list of partial session ids, return a set of those
        which no longer exist in Redis. Used by res.device.log to
        determine which sessions have been revoked.
        """
        identifiers = set(identifiers)
        not_found = set()
        for partial_sid in identifiers:
            key = f"{self.prefix}{partial_sid}*"
            match = self.redis.keys(pattern=key)
            if not match:
                not_found.add(partial_sid)
        return not_found

    def vacuum(self, *args, **kwargs):
        """Do not garbage collect the sessions.

        Redis keys are automatically cleaned at the end of their
        expiration.
        """
        return None