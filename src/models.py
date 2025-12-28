from __future__ import annotations

import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Self

from peewee import (
    AutoField,
    BooleanField,
    CharField,
    DateTimeField,
    DoesNotExist,
    ForeignKeyField,
    Model,
    SqliteDatabase,
    TextField,
)
from werkzeug.security import check_password_hash, generate_password_hash

from src import config


# Register datetime adapter and converter for SQLite
# This ensures datetime objects are properly serialized/deserialized
def _adapt_datetime(dt: datetime) -> str:
    """Convert datetime to ISO format string for SQLite storage."""
    return dt.isoformat()


def _convert_datetime(val: bytes | str) -> datetime:
    """Convert ISO format string back to datetime."""
    if isinstance(val, bytes):
        val = val.decode("utf-8")
    if "+" in val or val.endswith("Z"):
        if val.endswith("Z"):
            val = val[:-1] + "+00:00"
        return datetime.fromisoformat(val)
    return datetime.fromisoformat(val).replace(tzinfo=UTC)


sqlite3.register_adapter(datetime, _adapt_datetime)
sqlite3.register_converter("datetime", _convert_datetime)
sqlite3.register_converter("DATETIME", _convert_datetime)
sqlite3.register_converter("timestamp", _convert_datetime)
sqlite3.register_converter("TIMESTAMP", _convert_datetime)

db = SqliteDatabase(
    config.DATABASE_PATH,
    pragmas={
        "journal_mode": "wal",
        "foreign_keys": 1,
    },
    detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
)


class BaseModel(Model):
    id: int
    DoesNotExist: type[DoesNotExist]
    created_at: datetime

    id = AutoField(primary_key=True)
    created_at = DateTimeField(default=lambda: datetime.now(tz=UTC))

    class Meta:
        database = db


class User(BaseModel):
    username: str
    password_hash: str

    username = CharField(unique=True)
    password_hash = CharField()

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Client(BaseModel):
    client_id: str
    client_secret: str
    name: str
    redirect_uris: str  # Space-separated URIs
    allowed_scopes: str  # Space-separated scopes

    client_id = CharField(unique=True)
    client_secret = CharField()
    name = CharField()
    redirect_uris = TextField()
    allowed_scopes = TextField(default="openid profile email")

    def get_redirect_uris(self) -> list[str]:
        return self.redirect_uris.split() if self.redirect_uris else []

    def get_allowed_scopes(self) -> list[str]:
        return self.allowed_scopes.split() if self.allowed_scopes else []

    def validate_redirect_uri(self, uri: str) -> bool:
        return uri in self.get_redirect_uris()

    def validate_scopes(self, scopes: str | list[str]) -> bool:
        allowed = set(self.get_allowed_scopes())
        requested = set(scopes.split()) if isinstance(scopes, str) else set(scopes)
        return requested.issubset(allowed)


class AuthorizationCode(BaseModel):
    code: str
    client: Client
    user: User
    redirect_uri: str
    scopes: str
    expires_at: datetime
    used: bool

    code = CharField(unique=True)
    client = ForeignKeyField(Client, backref="auth_codes")
    user = ForeignKeyField(User, backref="auth_codes")
    redirect_uri = CharField()
    scopes = TextField()
    expires_at = DateTimeField()
    used = BooleanField(default=False)

    @classmethod
    def create_code(
        cls,
        client: Client,
        user: User,
        redirect_uri: str,
        scopes: str,
    ) -> Self:
        code = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(
            seconds=config.AUTHORIZATION_CODE_EXPIRES_IN
        )
        return cls.create(
            code=code,
            client=client,
            user=user,
            redirect_uri=redirect_uri,
            scopes=scopes,
            expires_at=expires_at,
        )

    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at


class AccessToken(BaseModel):
    token: str
    client: Client
    user: User | None
    scopes: str
    expires_at: datetime
    revoked: bool

    token = CharField(unique=True)
    client = ForeignKeyField(Client, backref="access_tokens")
    user = ForeignKeyField(User, backref="access_tokens", null=True)
    scopes = TextField()
    expires_at = DateTimeField()
    revoked = BooleanField(default=False)

    @classmethod
    def create_token(
        cls,
        client: Client,
        scopes: str,
        user: User | None = None,
        expires_in: int | None = None,
    ) -> Self:
        if expires_in is None:
            expires_in = config.ACCESS_TOKEN_EXPIRES_IN
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        return cls.create(
            token=token,
            client=client,
            user=user,
            scopes=scopes,
            expires_at=expires_at,
        )

    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()


class RefreshToken(BaseModel):
    token: str
    access_token: AccessToken
    expires_at: datetime
    revoked: bool

    token = CharField(unique=True)
    access_token = ForeignKeyField(AccessToken, backref="refresh_tokens")
    expires_at = DateTimeField()
    revoked = BooleanField(default=False)

    @classmethod
    def create_token(
        cls,
        access_token: AccessToken,
        expires_in: int | None = None,
    ) -> Self:
        if expires_in is None:
            expires_in = config.REFRESH_TOKEN_EXPIRES_IN
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        return cls.create(
            token=token,
            access_token=access_token,
            expires_at=expires_at,
        )

    def is_expired(self) -> bool:
        return datetime.now(UTC) > self.expires_at

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()


def init_db() -> None:
    db.connect(reuse_if_open=True)
    db.create_tables([User, Client, AuthorizationCode, AccessToken, RefreshToken])


def create_test_data() -> None:
    """Create test user and client for development."""
    init_db()

    # Create test user if not exists
    try:
        User.get(User.username == config.TEST_USER_USERNAME)
    except User.DoesNotExist:
        user = User(username=config.TEST_USER_USERNAME)
        user.set_password(config.TEST_USER_PASSWORD)
        user.save()

    # Create test client if not exists
    Client.get_or_create(
        client_id=config.TEST_CLIENT_ID,
        defaults={
            "client_secret": config.TEST_CLIENT_SECRET,
            "name": config.TEST_CLIENT_NAME,
            "redirect_uris": config.TEST_CLIENT_REDIRECT_URIS,
            "allowed_scopes": config.TEST_CLIENT_SCOPES,
        },
    )
