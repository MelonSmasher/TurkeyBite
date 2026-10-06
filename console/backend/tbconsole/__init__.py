"""TurkeyBite Console: search, analytics, findings and alerting for TurkeyBite.

The console runs on its own server, away from the TurkeyBite cluster. Events
stay in OpenSearch, which the console only reads. Postgres holds what is the
console's own: accounts and sessions, API keys, rules, the findings rules
raise, webhooks and their deliveries, dashboards and saved searches, the audit
log, and daily counts kept for trends that outlive index retention.
"""

__version__ = '0.1.0'
