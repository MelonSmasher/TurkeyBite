"""Settings, read once from the environment.

Everything is prefixed TBCONSOLE_. Secrets, the database and the OpenSearch
connection come from here rather than from the UI, so a console that cannot
reach its database still knows where its database is, and no secret is ever
stored where the console's own admins could read it back. Settings an admin
changes at runtime, such as the LDAP directory, live in the database instead.
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent


def _split(value):
    """A comma-separated environment variable as a list; a JSON list also works."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith('['):
            return json.loads(text)
        return [part.strip() for part in text.split(',') if part.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix='TBCONSOLE_', env_file=None,
                                      extra='ignore')

    # -- the console itself -------------------------------------------------
    database_url: str = 'postgresql+asyncpg://tbconsole:tbconsole-dev@127.0.0.1:55432/tbconsole'
    # The database password on its own, so one with @, / or : in it need not
    # be escaped into the URL. Overrides any password in the URL.
    database_password: str | None = None
    # Encrypts the secrets the database holds, such as webhook signing keys
    # and the LDAP bind password, and keys every HMAC the console makes.
    # Changing it makes those unreadable; list the old one in
    # secret_key_previous while re-saving them.
    secret_key: str = Field(min_length=32)
    secret_key_previous: Annotated[list[str], NoDecode] = []
    # Where people reach the console, for links in alerts
    public_url: str = 'http://localhost:8710'
    # Off only for plain-http development; a session cookie sent in clear
    # is a session anyone on the path can take
    cookie_secure: bool = True
    session_idle_minutes: int = Field(12 * 60, ge=5, le=30 * 24 * 60)
    session_max_hours: int = Field(7 * 24, ge=1, le=90 * 24)
    login_max_failures: int = Field(5, ge=1, le=100)
    login_lockout_minutes: int = Field(15, ge=1, le=24 * 60)
    # Run the rule scheduler, webhook dispatcher and rollups in this process.
    # Turn off on extra API-only replicas; any number may run them, since
    # work is claimed with SKIP LOCKED.
    run_workers: bool = True
    # The built frontend. Absent means API only, for development with Vite.
    static_dir: Path | None = PACKAGE_DIR / 'static'
    # Created at start when the database has no users at all, so a fresh
    # container can be signed in to. Ignored once any user exists.
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None
    # Record every search in the audit log, not only exports and entity
    # profiles. Off by default: the log would grow with every keystroke-driven
    # query, and the searches that matter for accountability are the ones
    # that name a person, which entity views already record.
    audit_all_searches: bool = False
    # How long the console keeps its own records. Closed findings and the
    # audit log for a year by default; set 0 to keep them for ever.
    finding_retention_days: int = Field(365, ge=0)
    audit_retention_days: int = Field(365, ge=0)
    # Webhook deliveries that were sent or gave up
    delivery_retention_days: int = Field(30, ge=1)
    # How often directory accounts are checked against the directory, so
    # someone removed from its groups loses access without signing in again
    ldap_recheck_minutes: int = Field(60, ge=5)
    # Rules look at events up to this many seconds ago rather than up to now,
    # so events still on their way into OpenSearch when a rule runs are
    # counted by the run that covers them, not missed by every run
    rule_ingest_delay_sec: int = Field(60, ge=0, le=3600)

    # -- OpenSearch or Elasticsearch, read only ---------------------------------
    opensearch_urls: Annotated[list[str], NoDecode] = ['http://127.0.0.1:59200']
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_verify_certs: bool = True
    opensearch_ca_certs: Path | None = None
    opensearch_index: str = 'tb-index-*'
    opensearch_timeout_sec: float = Field(30.0, gt=0, le=300)

    # -- webhooks -------------------------------------------------------------
    # Webhook URLs may not point at private, loopback or link-local addresses
    # unless this is on, so an admin account cannot be turned into a way to
    # probe the console's own network. Turn on for an alert receiver on the
    # LAN, such as a self-hosted chat server.
    webhook_allow_private: bool = False
    webhook_timeout_sec: float = Field(10.0, gt=0, le=120)
    # An HTTP proxy every webhook goes through, when the console's network has
    # no direct way out. The proxy then connects to the receiver itself, so
    # what it may reach is its rules' to decide; the console still refuses
    # URLs whose names resolve, for it, to addresses webhooks may not reach.
    webhook_proxy: str | None = None

    @field_validator('opensearch_urls', mode='before')
    @classmethod
    def _split_urls(cls, value):
        return _split(value)

    @field_validator('secret_key_previous', mode='before')
    @classmethod
    def _split_keys(cls, value):
        return _split(value)

    @field_validator('public_url')
    @classmethod
    def _strip_slash(cls, value):
        return value.rstrip('/')

    @field_validator('opensearch_ca_certs', 'static_dir', mode='before')
    @classmethod
    def _empty_path(cls, value):
        # An empty variable means none, not the current directory
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @model_validator(mode='after')
    def _password_into_url(self):
        if self.database_password:
            from sqlalchemy.engine import make_url
            url = make_url(self.database_url)
            if not url.username:
                raise ValueError('TBCONSOLE_DATABASE_PASSWORD needs a user name in '
                                 'TBCONSOLE_DATABASE_URL, such as postgresql+asyncpg://tbconsole@host/db')
            url = url.set(password=self.database_password)
            self.database_url = url.render_as_string(hide_password=False)
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
