"""The console's HTTP API, versioned under /api/v1.

The browser app and integrations use the same routes; the app signs in with a
session cookie, integrations with an API key in the Authorization header.
OpenAPI documentation is served at /api/docs.
"""

from fastapi import APIRouter

from . import (account, analytics, apikeys, audit, auth, dashboards, devices, entities, events,
               findings, rules, settings, system, users, webhooks)

router = APIRouter(prefix='/api/v1')
for module in (auth, account, events, analytics, entities, devices, findings, rules, dashboards,
               webhooks, apikeys, users, settings, audit, system):
    router.include_router(module.router)
