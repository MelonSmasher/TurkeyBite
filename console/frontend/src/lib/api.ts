// The one way the app talks to the API.
//
// Cookies carry the session; every request that changes something echoes the
// CSRF cookie in a header, which a cross-site page cannot read to copy. A 401
// anywhere sends the person back to sign in, remembering where they were.

export interface QueryError {
  message: string;
  position: number;
  length: number;
}

export class ApiError extends Error {
  status: number;
  detail: string;
  queryError?: QueryError;
  code?: string;

  constructor(status: number, detail: string, queryError?: QueryError, code?: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
    this.queryError = queryError;
    this.code = code;
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)tbc_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

const ZONE = (() => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
})();

let onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(handler: () => void) {
  onUnauthorized = handler;
}

export async function request<T = unknown>(method: string, path: string, body?: unknown,
                                           opts: { signal?: AbortSignal; raw?: boolean } = {}): Promise<T> {
  // Days round to this browser's midnight: "today" means today here
  const headers: Record<string, string> = { Accept: 'application/json', 'X-Timezone': ZONE };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && method !== 'HEAD') headers['X-CSRF-Token'] = csrfToken();
  let response: Response;
  try {
    response = await fetch(`/api/v1${path}`, {
      method, headers, credentials: 'same-origin', signal: opts.signal,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e;
    throw new ApiError(0, 'The console could not be reached. Check your connection.');
  }
  if (response.status === 401 && !path.startsWith('/auth/')) {
    onUnauthorized?.();
  }
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    let queryError: QueryError | undefined;
    let code: string | undefined;
    try {
      const data = await response.json();
      if (typeof data.detail === 'string') detail = data.detail;
      queryError = data.query_error;
      code = data.code;
    } catch {
      /* not JSON */
    }
    throw new ApiError(response.status, detail, queryError, code);
  }
  if (opts.raw) return response as unknown as T;
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  get: <T = unknown>(path: string, opts?: { signal?: AbortSignal }) => request<T>('GET', path, undefined, opts),
  post: <T = unknown>(path: string, body?: unknown, opts?: { signal?: AbortSignal }) =>
    request<T>('POST', path, body ?? {}, opts),
  put: <T = unknown>(path: string, body?: unknown) => request<T>('PUT', path, body ?? {}),
  patch: <T = unknown>(path: string, body?: unknown) => request<T>('PATCH', path, body ?? {}),
  del: <T = unknown>(path: string) => request<T>('DELETE', path),
};

export function qs(params: Record<string, string | number | boolean | null | undefined | string[]>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) value.forEach((v) => search.append(key, v));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : '';
}

/** Downloads a POST response as a file, for exports. */
export async function download(path: string, body: unknown, fallbackName: string): Promise<void> {
  const response = await request<Response>('POST', path, body, { raw: true });
  const blob = await response.blob();
  const disposition = response.headers.get('content-disposition') || '';
  const name = disposition.match(/filename="([^"]+)"/)?.[1] ?? fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
