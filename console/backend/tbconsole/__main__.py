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

    from . import db
    from .models import User
    from .security import passwords, rbac
    if args.role not in rbac.ROLES:
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
        if user is None:
            user = User(username=args.username, source='local', role=args.role, preferences={})
            session.add(user)
        user.role = args.role
        user.password_hash = passwords.hash_password(password)
        user.disabled = False
        user.locked_until = None
        await session.commit()
    await db.dispose()
    print(f'{args.username} is a local {args.role}.')
    return 0


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
    p.add_argument('--role', default='admin')
    p.add_argument('--password-stdin', action='store_true')

    p = sub.add_parser('rollups', help='recount the daily statistics')
    p.add_argument('--backfill', action='store_true')

    p = sub.add_parser('demo', help='load made-up data, for trying the console out')
    p.add_argument('action', choices=['seed', 'feed', 'sink'])
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
    if args.command == 'rollups':
        return asyncio.run(run_rollups(args))
    if args.command == 'demo':
        from .demo import feed, seed, start_sink
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
