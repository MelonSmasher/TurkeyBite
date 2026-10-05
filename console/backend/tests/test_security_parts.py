"""The pieces security rests on: hashing, encryption, signing, URL checks, LDAP."""

import ipaddress
import time

import pyotp
import pytest
from ldap3 import MOCK_SYNC, OFFLINE_SLAPD_2_4, Connection, Server

from tbconsole.config import get_settings
from tbconsole.security import apikeys, crypto, ldap, passwords, totp
from tbconsole.webhooks import dispatcher, formats, safety, signing


def test_passwords_hash_and_verify():
    stored = passwords.hash_password('correct horse battery')
    assert stored.startswith('$argon2id$')
    assert passwords.verify_password(stored, 'correct horse battery')
    assert not passwords.verify_password(stored, 'wrong')
    assert not passwords.verify_password(None, 'anything')


def test_password_rules_are_explained():
    assert passwords.password_problems('short', 'x')
    assert any('username' in p for p in passwords.password_problems('alice-alice-alice', 'alice'))
    assert passwords.password_problems('a much better passphrase', 'alice') == []


def test_api_keys_are_random_and_only_their_hash_matches():
    key, prefix, digest = apikeys.generate()
    other, _, _ = apikeys.generate()
    assert key != other and key.startswith(f'tbc_{prefix}_')
    assert apikeys.parse(key) == prefix
    assert apikeys.matches(key, digest) and not apikeys.matches(other, digest)
    assert apikeys.parse('tbc_short_x') is None and apikeys.parse('Bearer nonsense') is None


def test_secrets_round_trip_and_survive_a_key_rotation(monkeypatch):
    sealed = crypto.encrypt('bind password')
    assert crypto.decrypt(sealed) == 'bind password'
    settings = get_settings()
    old = settings.secret_key
    monkeypatch.setattr(settings, 'secret_key', 'a brand new key that is also long enough!!')
    with pytest.raises(crypto.SecretUnreadable):
        crypto.decrypt(sealed)
    monkeypatch.setattr(settings, 'secret_key_previous', [old])
    assert crypto.decrypt(sealed) == 'bind password'


def test_totp_accepts_a_neighbouring_step_and_refuses_replays():
    secret = totp.new_secret()
    now = time.time()
    code = pyotp.TOTP(secret).at(now - 30)
    step = totp.verify(secret, code, None, now)
    assert step is not None
    assert totp.verify(secret, code, step, now) is None
    assert totp.verify(secret, '12345', None, now) is None


def test_signatures_verify_and_expire():
    body = b'{"event":"test"}'
    header = signing.sign('whsec_x', body, timestamp=1000)
    assert signing.verify('whsec_x', body, header, now=1100)
    assert not signing.verify('whsec_y', body, header, now=1100)
    assert not signing.verify('whsec_x', body + b' ', header, now=1100)
    assert not signing.verify('whsec_x', body, header, now=1000 + signing.TOLERANCE_SECONDS + 1)


@pytest.mark.parametrize('fmt', list(formats.FORMATS))
def test_every_format_renders_a_finding_and_a_test(fmt):
    finding = {'event': 'finding.created', 'url': 'https://console/findings/1',
               'finding': {'title': 'Threat seen: ava', 'summary': '3 events', 'severity': 'critical', 'status': 'new',
                           'rule_name': 'Threat seen', 'entity': 'ava', 'event_count': 3,
                           'top_domains': [{'key': 'evil.example', 'count': 3}]}}
    assert formats.render(fmt, finding)
    assert formats.render(fmt, {'event': 'test', 'message': 'hello'})


def test_private_addresses_are_blocked_unless_allowed():
    blocked = [ipaddress.ip_address(a) for a in ('127.0.0.1', '10.1.2.3', '192.168.0.1', '169.254.169.254', '::1', '0.0.0.0')]
    for address in blocked:
        assert safety._blocked(address, allow_private=False), address
    assert not safety._blocked(ipaddress.ip_address('93.184.215.14'), allow_private=False)
    # Allowing private never opens the metadata service
    assert safety._blocked(ipaddress.ip_address('169.254.169.254'), allow_private=True)
    assert not safety._blocked(ipaddress.ip_address('10.1.2.3'), allow_private=True)


async def test_a_name_that_resolves_to_a_private_address_is_refused():
    with pytest.raises(safety.UnsafeUrl, match='may not reach'):
        await safety.check('http://localhost:9/hook')


def test_deliveries_back_off_then_die():
    class Row:
        attempts = 0
        status = 'pending'
        next_attempt_at = None
        delivered_at = None
        last_status_code = last_error = response_snippet = duration_ms = None

    class Hook:
        failure_streak = 0
        last_status = last_delivery_at = None
    from datetime import datetime, timezone
    row, hook = Row(), Hook()
    now = datetime.now(timezone.utc)
    failure = {'status_code': 503, 'error': 'HTTP 503', 'snippet': '', 'retry': True, 'duration_ms': 5}
    for expected in dispatcher.BACKOFF:
        dispatcher.apply(row, hook, failure, now)
        assert row.status == 'failed'
        assert int((row.next_attempt_at - now).total_seconds()) == expected
    dispatcher.apply(row, hook, failure, now)
    assert row.status == 'dead' and hook.failure_streak == dispatcher.MAX_ATTEMPTS
    refused = Row()
    dispatcher.apply(refused, hook, {'status_code': 404, 'error': 'refused', 'snippet': '', 'retry': False, 'duration_ms': 5}, now)
    assert refused.status == 'dead' and refused.attempts == 1


# -- LDAP, against ldap3's in-memory directory ------------------------------------------

@pytest.fixture
def directory(monkeypatch):
    server = Server('mock', get_info=OFFLINE_SLAPD_2_4)
    seed = Connection(server, user='cn=svc,dc=example,dc=org', password='svc-pw', client_strategy=MOCK_SYNC)
    seed.strategy.add_entry('cn=svc,dc=example,dc=org', {'userPassword': 'svc-pw', 'objectClass': 'person', 'sn': 'svc'})
    seed.strategy.add_entry('uid=ava,ou=people,dc=example,dc=org', {
        'userPassword': 'ava-pw', 'objectClass': ['person', 'inetOrgPerson'], 'uid': 'ava', 'sn': 'Chen',
        'displayName': 'Ava Chen', 'mail': 'ava@example.org',
        'memberOf': ['cn=safeguarding,ou=groups,dc=example,dc=org']})
    seed.strategy.add_entry('uid=bob,ou=people,dc=example,dc=org', {
        'userPassword': 'bob-pw', 'objectClass': ['person', 'inetOrgPerson'], 'uid': 'bob', 'sn': 'B',
        'memberOf': ['cn=students,ou=groups,dc=example,dc=org']})
    monkeypatch.setattr(ldap, '_STRATEGY', MOCK_SYNC)
    monkeypatch.setattr(ldap, '_MOCK_SERVER', server)
    return ldap.config_with_defaults({
        'enabled': True, 'urls': ['ldap://mock'], 'bind_dn': 'cn=svc,dc=example,dc=org',
        'user_base_dn': 'ou=people,dc=example,dc=org', 'user_filter': '(&(objectClass=person)(uid={username}))',
        'role_mappings': [{'group': 'cn=safeguarding,ou=groups,dc=example,dc=org', 'role': 'analyst'},
                          {'group': 'CN=IT,ou=groups,dc=example,dc=org', 'role': 'admin'}]})


def test_ldap_signs_someone_in_with_the_role_their_groups_give(directory):
    identity = ldap.authenticate(directory, 'svc-pw', 'ava', 'ava-pw')
    assert identity.role == 'analyst' and identity.display_name == 'Ava Chen' and identity.email == 'ava@example.org'


def test_ldap_refuses_a_wrong_password_and_an_unknown_person_alike(directory):
    with pytest.raises(ldap.LdapInvalidCredentials):
        ldap.authenticate(directory, 'svc-pw', 'ava', 'wrong')
    with pytest.raises(ldap.LdapInvalidCredentials):
        ldap.authenticate(directory, 'svc-pw', 'nobody', 'x')


def test_ldap_never_sends_an_empty_password(directory):
    with pytest.raises(ldap.LdapInvalidCredentials):
        ldap.authenticate(directory, 'svc-pw', 'ava', '')


def test_ldap_refuses_someone_in_no_mapped_group_unless_there_is_a_default(directory):
    with pytest.raises(ldap.LdapNotPermitted):
        ldap.authenticate(directory, 'svc-pw', 'bob', 'bob-pw')
    directory['default_role'] = 'viewer'
    assert ldap.authenticate(directory, 'svc-pw', 'bob', 'bob-pw').role == 'viewer'


def test_ldap_filter_injection_finds_nobody(directory):
    with pytest.raises(ldap.LdapInvalidCredentials):
        ldap.authenticate(directory, 'svc-pw', '*)(uid=*', 'ava-pw')


def test_a_wrong_service_password_means_the_directory_is_unavailable(directory):
    with pytest.raises(ldap.LdapUnavailable):
        ldap.authenticate(directory, 'not-the-svc-pw', 'ava', 'ava-pw')


def test_role_mapping_is_case_insensitive_and_takes_the_highest():
    cfg = ldap.config_with_defaults({'role_mappings': [{'group': 'cn=a', 'role': 'viewer'}, {'group': 'CN=B', 'role': 'admin'}]})
    assert ldap.map_role(cfg, ['CN=A', 'cn=b']) == 'admin'
    assert ldap.map_role(cfg, ['cn=c']) is None


def test_the_ldap_test_reports_each_step(directory):
    steps = ldap.test(directory, 'svc-pw', 'ava', 'ava-pw')
    assert [s['ok'] for s in steps] == [True, True, True, True, True]
    assert steps[3]['detail'] == 'analyst'
