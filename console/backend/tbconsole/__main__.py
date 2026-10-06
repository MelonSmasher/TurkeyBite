"""python -m tbconsole: run the console, migrate its database, manage users, load a demo."""

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path


def _alembic_config():
    from alembic.config import Config
    root = Path(__file__).resolve().parent.parent
    config = Config(str(root / 'alembic.ini'))
    config.set_main_option('script_location', str(Path(__file__).resolve().parent / 'migrations'))
    return config


def migrate() -> None:
    from alembic import command
    command.upgrade(_alembic_config(), 'head')


def serve(args) -> None:
    import uvicorn
    if args.migrate:
        migrate()
    uvicorn.run('tbconsole.main:create_app', factory=True, host=args.host, port=args.port,
                proxy_headers=True,
                forwarded_allow_ips=os.environ.get('TBCONSOLE_FORWARDED_ALLOW_IPS', '127.0.0.1'),
                log_level=args.log_level)


async def create_user(args) -> int:
    from sqlalchemy import func, select

    from datetime import datetime, timezone

    from sqlalchemy import update

    from . import audit, db
    from .models import ApiKey, User
    from .security import passwords, rbac, sessions
    if args.role is not None and args.role not in rbac.ROLES:
        print(f'role is one of {", ".join(rbac.ROLES)}', file=sys.stderr)
        return 2
    password = sys.stdin.readline().rstrip('\n') if args.password_stdin else getpass.getpass(
        f'Password for {args.username}: ')
    problems = passwords.password_problems(password, args.username)
    if problems:
        print(' '.join(problems), file=sys.stderr)
        return 2
    async with db.sessionmaker()() as session:
        user = (await session.execute(select(User).where(
            func.lower(User.username) == args.username.lower()))).scalar_one_or_none()
        if user is not None and user.source != 'local':
            print(f'{args.username} exists and is not a local account', file=sys.stderr)
            return 1
        created = user is None
        if created:
            user = User(username=args.username, source='local', role=args.role or 'admin',
                        preferences={})
            session.add(user)
        elif args.role:
            user.role = args.role
        user.password_hash = passwords.hash_password(password)
        user.password_changed_at = datetime.now(timezone.utc)
        notes = []
        if args.reset_mfa:
            # For someone who lost their authenticator, and with it the only way in
            user.totp_enabled = False
            user.totp_secret_enc = None
            user.totp_last_step = None
        if user.disabled and not args.enable:
            notes.append('it stays disabled; add --enable to turn it back on')
        elif user.disabled:
            user.disabled = False
            user.disabled_reason = None
        user.locked_until = None
        user.failed_logins = 0
        if args.revoke_keys and not created:
            # A reset after a compromise: the keys may be compromised too
            revoked = (await session.execute(
                update(ApiKey).where(ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None))
                .values(revoked_at=datetime.now(timezone.utc)))).rowcount
            notes.append(f'{revoked} API key{"s" if revoked != 1 else ""} revoked')
        await session.flush()
        if not created:
            # A reset password is often a reset because the old one leaked
            await sessions.end_all(session, user.id)
        audit.record(session, 'user.create' if created else 'user.password_reset',
                     actor_type='cli', actor_name='tbconsole create-user', target_type='user',
                     target_id=user.id, target_label=user.username,
                     details={'role': user.role, 'mfa_reset': bool(args.reset_mfa),
                              'keys_revoked': bool(args.revoke_keys), 'enabled': bool(args.enable)})
        role = user.role
        await session.commit()
    await db.dispose()
    print(f'{args.username} is a local {role}' + ('.' if created else '; its sessions have ended')
          + ''.join(f'; {n}' for n in notes) + ('' if created else '.'))
    return 0


async def reencrypt(args) -> int:
    """Re-encrypts what the database holds under the current secret key, so the
    previous one can be removed from TBCONSOLE_SECRET_KEY_PREVIOUS."""
    from sqlalchemy import select

    from . import db, settings_store
    from .models import User, Webhook
    from .security import crypto

    done, unreadable = 0, []

    def again(token: str | None, what: str) -> str | None:
        nonlocal done
        if not token:
            return token
        try:
            value = crypto.encrypt(crypto.decrypt(token))
        except crypto.SecretUnreadable:
            unreadable.append(what)
            return token
        done += 1
        return value

    async with db.sessionmaker()() as session:
        for user in (await session.execute(select(User).where(User.totp_secret_enc.is_not(None)))).scalars():
            user.totp_secret_enc = again(user.totp_secret_enc, f'two-factor secret of {user.username}')
        for hook in (await session.execute(select(Webhook))).scalars():
            hook.secret_enc = again(hook.secret_enc, f'signing secret of webhook {hook.name}')
            hook.url_enc = again(hook.url_enc, f'URL of webhook {hook.name}')
            hook.headers_enc = again(hook.headers_enc, f'headers of webhook {hook.name}')
        ldap = await settings_store.get(session, 'ldap')
        if ldap.get('bind_password_enc'):
            ldap['bind_password_enc'] = again(ldap['bind_password_enc'], 'LDAP bind password')
            await settings_store.put(session, 'ldap', ldap, None)
        await session.commit()
    await db.dispose()
    print(f'{done} secrets encrypted under the current key.')
    for what in unreadable:
        print(f'Could not read the {what}: it was saved under a key that is no longer configured.',
              file=sys.stderr)
    return 1 if unreadable else 0


async def run_rollups(args) -> int:
    from . import db, rollups
    from .search.client import SearchClient
    search = SearchClient()
    try:
        days = await rollups.run(search, backfill=args.backfill)
    finally:
        await search.close()
        await db.dispose()
    print(f'Counted {days} days.')
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog='tbconsole', description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('serve', help='run the console')
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=8710)
    p.add_argument('--migrate', action='store_true', help='migrate the database first')
    p.add_argument('--log-level', default='info')

    sub.add_parser('migrate', help='bring the database schema up to date')

    p = sub.add_parser('create-user', help='create a local account, or reset its password')
    p.add_argument('username')
    p.add_argument('--role', choices=['viewer', 'analyst', 'admin'],
                   help='the role; admin for a new account, unchanged for an existing one')
    p.add_argument('--password-stdin', action='store_true')
    p.add_argument('--reset-mfa', action='store_true',
                   help='turn off two-factor sign-in, for someone who lost their authenticator')
    p.add_argument('--enable', action='store_true', help='turn a disabled account back on')
    p.add_argument('--revoke-keys', action='store_true',
                   help='revoke every API key the account holds, after a compromise')

    sub.add_parser('reencrypt', help='encrypt every stored secret again under the current '
                                     'TBCONSOLE_SECRET_KEY, to finish changing it')

    p = sub.add_parser('rollups', help='recount the daily statistics')
    p.add_argument('--backfill', action='store_true')

    p = sub.add_parser('demo', help='load made-up data, for trying the console out')
    p.add_argument('action', choices=['seed', 'feed', 'sink'])
    p.add_argument('--yes-replace-everything', action='store_true',
                   help='seed: deletes every tb-index-* index and empties the console\'s '
                        'database first')
    p.add_argument('--yes-write-events', action='store_true',
                   help='feed: writes made-up events to the cluster')
    p.add_argument('--days', type=int, default=21)
    p.add_argument('--per-day', type=int, default=12000)
    p.add_argument('--sink', default='http://127.0.0.1:8799',
                   help='a URL that accepts webhook deliveries, for the demo webhooks')

    args = parser.parse_args(argv)
    if args.command == 'serve':
        serve(args)
        return 0
    if args.command == 'migrate':
        migrate()
        return 0
    if args.command == 'create-user':
        return asyncio.run(create_user(args))
    if args.command == 'reencrypt':
        return asyncio.run(reencrypt(args))
    if args.command == 'rollups':
        return asyncio.run(run_rollups(args))
    if args.command == 'demo':
        try:
            from .demo import feed, seed, start_sink
        except ImportError:
            print('The demo is not part of this installation; it is for development.',
                  file=sys.stderr)
            return 2
        agreed = args.yes_replace_everything if args.action == 'seed' else args.yes_write_events
        if args.action in ('seed', 'feed') and not agreed:
            from .config import get_settings
            settings = get_settings()
            what = ('deletes every tb-index-* index on ' + ', '.join(settings.opensearch_urls)
                    + ' and empties the database at ' + settings.database_url.split('@')[-1]
                    if args.action == 'seed' else
                    'writes made-up events to ' + ', '.join(settings.opensearch_urls))
            flag = '--yes-replace-everything' if args.action == 'seed' else '--yes-write-events'
            print(f'demo {args.action} {what}. It is for a development cluster only. '
                  f'Run it again with {flag} if that is what you want.', file=sys.stderr)
            return 2
        if args.action == 'sink':
            import time
            server = start_sink(args.sink)
            if server is None:
                print(f'Something is already listening at {args.sink}.', file=sys.stderr)
                return 1
            print(f'Accepting demo webhook deliveries at {args.sink}. Ctrl-C to stop.')
            try:
                while True:
                    time.sleep(3600)
            except KeyboardInterrupt:
                server.shutdown()
                return 0
        if args.action == 'feed':
            try:
                return asyncio.run(feed(per_day=args.per_day))
            except KeyboardInterrupt:
                return 0
        migrate()
        return asyncio.run(seed(days=args.days, per_day=args.per_day, sink=args.sink))
    return 1


if __name__ == '__main__':
    sys.exit(main())
