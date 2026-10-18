# The API

Everything the app does goes through `/api/v1`, described at
`/api/openapi.json` and on the app's API reference page. Set
`TBCONSOLE_API_DOCS=true` for the interactive docs at `/api/docs`, which load
Swagger UI from a CDN. Integrations authenticate with an API key:

```sh
curl https://console.example.org/api/v1/findings?status=open -H "Authorization: Bearer tbc_…"
```

A key carries scopes, and does only what both its scopes and its owner's role
allow. Keys for integrations belong to service accounts, which cannot sign in and
outlive the person who made them.

## API keys

**Integrate → API keys** makes and revokes your own keys; it needs the **analyst** role. Admins manage every key, and service accounts, under **Admin → Users**. A key is shown once, when it is made, and only a hash of it is kept. Choose its scopes, the permissions it carries, and when it expires. A key used from a script should belong to a service account, so it outlives the person who made it.

Every request with a key is checked as the person's would be: its scopes, narrowed by its owner's role. A key cannot sign in, change a password or manage sessions.
