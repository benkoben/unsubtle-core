let refreshPromise = null;

async function apiFetch(input, init = {}) {
    const opts = { ...init, credentials: 'include' };
    let res = await fetch(input, opts);

    if (res.status !== 401 && res.status !== 419) return res;

    // One refresh in flight at a time
    if (!refreshPromise) {
        refreshPromise = fetch('/auth/refresh', { method: 'POST', credentials: 'include' })
            .finally(() => { refreshPromise = null; });
    }

    const refreshRes = await refreshPromise;
    if (!refreshRes.ok) {
        // Refresh failed -> force sign-out
        // e.g., redirect to /login or clear app state
        throw new Error('Session expired');
    }

    // New auth_token cookie is set. Retry original request once.
    return fetch(input, opts);
}
