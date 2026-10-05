"""How TurkeyBite connects to OpenSearch, checked once when a process starts.

Every document a worker ships holds per-user browsing data, so the connection
it travels over matters as much as the index it lands in.

The bundled OpenSearch serves the security plugin's demo certificates, which
no client trusts out of the box, so certificate verification has always been
off. Turning it on by default would stop every existing install from shipping,
so it stays off unless a host asks for it with `verify_certs`. What changes is
that the choice is no longer silent: a process that will talk to an https host
without verifying it says so once, at start, naming the host and the fix.

The admin password is checked too. Changeit12345! shipped as the OpenSearch
admin password in setup.py, the example environment and the example
configuration, so anyone who has read this repository knows it, and the admin
account can read and delete every event. A host configured with it is refused.
TURKEYBITE_ALLOW_DEFAULT_PASSWORD=yes lets it through, loudly, for a disposable
test install that holds no real traffic.

Settings are checked when the process starts rather than when the first event
is shipped, so a mistake such as a CA file that is not where the configuration
says stops the worker with a clear message instead of costing every event.
"""

import os
import sys
from urllib.parse import urlparse


def _warn(message):
    print(message, file=sys.stderr)


# Hosts this process has already warned about, keyed on pid as well, so a
# forked child that checks its own settings still says so once for itself
_warned = set()

# The admin password TurkeyBite used to ship with, and the variable that lets a
# disposable test install keep using it
DEFAULT_PASSWORD = 'Changeit12345!'
ALLOW_DEFAULT_PASSWORD = 'TURKEYBITE_ALLOW_DEFAULT_PASSWORD'


def default_password_allowed(environ=None):
    """True when TURKEYBITE_ALLOW_DEFAULT_PASSWORD is exactly yes.

    Exactly, rather than anything truthy, so the escape hatch is opened only by
    someone who read what it is for.
    """
    environ = os.environ if environ is None else environ
    return (environ.get(ALLOW_DEFAULT_PASSWORD) or '').strip() == 'yes'


def check_password(password, where, environ=None, log=_warn):
    """Refuses the password TurkeyBite used to ship with. Raises ValueError.

    `where` names the setting, so the message says what to change. With the
    escape hatch open the password is let through and `log` is told, loudly,
    once per process for each setting.
    """
    if not isinstance(password, str) or password.strip() != DEFAULT_PASSWORD:
        return
    if default_password_allowed(environ):
        key = (os.getpid(), 'default password', where)
        if key not in _warned:
            _warned.add(key)
            log(f'WARNING: {where} is {DEFAULT_PASSWORD}, the OpenSearch admin password '
                f'TurkeyBite used to ship with, which anyone can look up. '
                f'{ALLOW_DEFAULT_PASSWORD}=yes lets it through. Do this only on a '
                f'disposable test install that holds no real traffic.')
        return
    raise ValueError(
        f'{where} is {DEFAULT_PASSWORD}, the OpenSearch admin password TurkeyBite used '
        f'to ship with, which anyone who has read the repository knows. Refusing to '
        f'start. Change the admin password in OpenSearch, then here and in .env: see '
        f'"Changing the OpenSearch admin password" in the README. On a disposable test '
        f'install only, set {ALLOW_DEFAULT_PASSWORD}=yes to start anyway.')


def tls_settings(host, where):
    """(verify_certs, ca_certs) for one processor.elastic.hosts entry, checked.

    Absent means (False, None), which is how every host behaved before these
    settings existed. Raises ValueError for a value of the wrong type, or for a
    ca_certs path that is not a file, naming `where` so the operator knows
    which entry to fix.
    """
    verify = host.get('verify_certs', False)
    if not isinstance(verify, bool):
        raise ValueError(f'{where} verify_certs must be true or false, not {verify!r}')
    ca_certs = host.get('ca_certs')
    if ca_certs is not None:
        if not isinstance(ca_certs, str) or not ca_certs.strip():
            raise ValueError(f'{where} ca_certs must be the path to a CA certificate '
                             f'file, not {ca_certs!r}')
        if not os.path.isfile(ca_certs):
            raise ValueError(f'{where} ca_certs is {ca_certs}, which is not a file in '
                             f'this container. Mount the CA certificate into every '
                             f'container that reads config.yaml.')
    return verify, ca_certs


def unverified(host):
    """True when the host is reached over TLS without checking its certificate.

    Plain http is not reported: there is no certificate to check, and nothing
    about it changed.
    """
    return (urlparse(host.get('uri') or '').scheme == 'https'
            and host.get('verify_certs') is not True)


def unverified_warning(host):
    """The line a process logs, once, for a host it will use unverified."""
    hint = ''
    if host.get('ca_certs'):
        hint = ' ca_certs is set, but has no effect until verify_certs is true.'
    return (f'WARNING: OpenSearch at {host.get("uri")} is used without verifying its '
            f'certificate, so anything able to intercept the connection can read every '
            f'event and the password sent with it.{hint} Set verify_certs: true and '
            f'ca_certs for this host; see "Verifying OpenSearch\'s certificate" in the '
            f'README.')


def client_kwargs(host):
    """Keyword arguments for opensearchpy.OpenSearch for one host entry.

    The one place a client's connection settings are decided, shared by the
    workers and the librarian so the two cannot drift.
    """
    parsed = urlparse(host['uri'])
    use_ssl = parsed.scheme == 'https'
    verify, ca_certs = tls_settings(host, host['uri'])
    kwargs = {
        'hosts': [{'host': parsed.hostname, 'port': parsed.port or (443 if use_ssl else 80)}],
        'use_ssl': use_ssl,
        'verify_certs': verify,
        # urllib3 would otherwise warn on every request to an unverified host.
        # One warning at start says the same thing without burying the log.
        'ssl_show_warn': False,
        'request_timeout': 30,
        'retry_on_timeout': True,
    }
    if verify and ca_certs:
        kwargs['ca_certs'] = ca_certs
    if host.get('username') and host.get('password'):
        kwargs['http_auth'] = (host['username'], host['password'])
    return kwargs


def check_hosts(elastic, environ=None, log=_warn):
    """Checks processor.elastic once at start. Raises ValueError on a mistake.

    A host configured with the default admin password is a mistake, see
    `check_password`. Nothing is checked when OpenSearch output is off, since
    the hosts are then never used, and a syslog-only deployment should not be
    stopped by settings it does not read. Each host used without verification
    is reported once per process through `log`, however many processors the
    process builds.
    """
    elastic = elastic or {}
    if not elastic.get('enable'):
        return
    hosts = elastic.get('hosts') or []
    if not isinstance(hosts, list):
        raise ValueError(f'processor.elastic.hosts must be a list, not {hosts!r}')
    for i, host in enumerate(hosts):
        where = f'processor.elastic.hosts[{i}]'
        if not isinstance(host, dict) or not isinstance(host.get('uri'), str):
            raise ValueError(f'{where} must be a mapping with a uri, not {host!r}')
        tls_settings(host, where)
        check_password(host.get('password'), f'{where} password', environ, log)
        key = (os.getpid(), host['uri'])
        if unverified(host) and key not in _warned:
            _warned.add(key)
            log(unverified_warning(host))
