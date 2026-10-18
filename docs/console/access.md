# Accounts, sign-in and roles

## Roles

| Role | Can |
|---|---|
| **viewer** | search events, read analytics, entities, dashboards, findings and rules |
| **analyst** | everything a viewer can, and export events, triage findings, write and test rules, build dashboards and saved searches, read webhooks, and hold API keys of their own |
| **admin** | everything, including users and service accounts, every API key, the directory and other settings, webhooks, and the audit log |

An API key carries scopes, which are permissions, and acts with only those its owner's role also has, so demoting someone narrows every key they hold.

## Local accounts and the bootstrap admin

The first admin comes from `TBCONSOLE_BOOTSTRAP_ADMIN_USERNAME` and `TBCONSOLE_BOOTSTRAP_ADMIN_PASSWORD` in `console.env`, and is made only when there are no accounts at all. Sign in as it, change its password, turn on its second factor, and remove the password from `console.env`. **Admin → Users** makes more local accounts and service accounts, sets roles, and disables accounts.

Each person turns on a TOTP second factor under **Your account**, with any authenticator app. Admins can require one for every local admin under **Admin → Authentication**.

## Signing in with LDAP

Under **Admin → Authentication**, give the directory's `ldaps://` URLs (or
`ldap://` with StartTLS), a service account that can search people, where to
search and with what filter, and map directory groups to roles. A person gets the
highest role any of their groups maps to, read again at every sign-in; someone
in no mapped group is refused unless a default role is set. **Try it** checks
each step with a real username, and says where it fails.

A username that belongs to a local account always signs in locally, whether the
directory is up or not; that is what local accounts are for. Five wrong
passwords or codes lock a local account for fifteen minutes
(`TBCONSOLE_LOGIN_MAX_FAILURES`, `TBCONSOLE_LOGIN_LOCKOUT_MINUTES`), ten failures
for one username from one address hold that pair back for five minutes, an
address with a hundred failures in five minutes is held back for the names it
has failed with but never for one it has not tried, and admins can require a
second factor for local admins. Each address (an IPv6 one by its /56) has two
sign-ins checked at a time and a queue of 64 behind them, past which it is
told to try again in a moment, so a flood from one address waits on itself
while every other address signs in as usual. People who share the flooding
address, behind one NAT, wait with it while it lasts: telling them apart by
whether their account exists would tell an attacker which accounts do. Each
account's password is checked once at a time, so guesses sent together still
stop at the lockout, and the directory being unreachable never counts against
anyone's name. Someone who lost their
authenticator gets back in with
`python -m tbconsole create-user NAME --password-stdin --reset-mfa`, which also
ends their sessions; their role stays as it was unless `--role` is given, a
disabled account stays disabled unless `--enable` is, and `--revoke-keys`
revokes every API key it holds, for a reset after a compromise; an admin
setting a new password on Users can revoke the keys too. Wrong passwords given
to confirm a change on the account page count against the same limits as
sign-ins, and lock the account the same way, and a sign-in from another site's
page is refused.

## Security, in short

-   Sessions are opaque tokens in HttpOnly, Secure, SameSite cookies, stored only as
    hashes, ending when idle, when old, when a password changes or an account is
    disabled. Every state-changing request must echo a CSRF token from a second
    cookie, a cross-site `Origin` is refused outright, and so is any request a
    browser marks as coming from another site, so a link elsewhere cannot make
    someone's browser look at a profile in their name.
-   Passwords are Argon2id. API keys are 256 random bits, kept as SHA-256 hashes and
    shown once. Webhook secrets, custom headers and the LDAP bind password are
    encrypted with a key derived from `TBCONSOLE_SECRET_KEY`.
-   Webhooks cannot point at loopback, private, link-local or cloud metadata
    addresses unless `TBCONSOLE_WEBHOOK_ALLOW_PRIVATE` is on; link-local and
    metadata addresses never. The check runs when a webhook is saved and again
    before every delivery, which then connects to the very address it checked,
    over a connection of its own, and reads at most the start of the answer.
-   Privacy mode shows people and machines as aliases everywhere a name would
    appear on screen: lists, charts and their tables, finding titles, queries, the
    query bar until you click into it, raw events, and the address bar. Exports,
    copied queries and the audit log keep the real values; they are records.
-   A strict Content-Security-Policy, `X-Frame-Options: DENY`, `no-store` on the
    API, and no inline script anywhere in the app.
-   Sign-ins, failed ones included, every change, every export and every look at a
    person's profile go to the audit log.
