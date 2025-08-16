async function checkAuthWithValidation() {
    const token = localStorage.getItem('token');

    // Basic presence check
    if (!token) {
        redirectToLogin();
        return;
    }

    // Client-side validation
    const validation = validateToken(token);
    if (!validation.valid) {
        console.warn('Token validation failed:', validation.reason);

        // Try to refresh token or redirect to login
        if (validation.reason === 'Token expired') {
            await attemptTokenRefresh();
        } else {
            logout();
        }
        return;
    }

    // Display user info from validated payload
    if (validation.payload.sub) {
        document.getElementById('user-email').textContent = validation.payload.sub;
    }

    // Optional: Validate with server periodically
    // await validateTokenWithServer(token);
}

function validateTokenWithServer(token) {

}

function redirectToLogin() {
    window.location.href = '/';
}

function validateToken(token) {
    if (!token) {
        return { valid: false, reason: 'No token provided' };
    }

    try {
        // Split token into parts
        const parts = token.split('.');
        if (parts.length !== 3) {
            return { valid: false, reason: 'Invalid token format' };
        }

        // Decode payload (without verification - server should verify signature)
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

        // Check expiration
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) {
            return { valid: false, reason: 'Token expired' };
        }

        // Check not before
        if (payload.nbf && payload.nbf > now) {
            return { valid: false, reason: 'Token not yet valid' };
        }

        // Check issued at (allow some clock skew)
        if (payload.iat && payload.iat > now + 300) { // 5 minutes skew
            return { valid: false, reason: 'Token issued in future' };
        }

        return { valid: true, payload };
    } catch (error) {
        return { valid: false, reason: 'Token parsing failed' };
    }
}
// logout removes tokens form localStorage and redirects the user to login
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    redirectToLogin();
}

async function attemptTokenRefresh() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) {
        redirectToLogin();
        return;
    }

    try {
        const response = await fetch('/refresh', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refreshToken })
        });

        if (response.ok) {
            const { token: newToken, refreshToken: newRefreshToken } = await response.json();
            localStorage.setItem('token', newToken);
            if (newRefreshToken) {
                localStorage.setItem('refreshToken', newRefreshToken);
            }
            // Retry the original operation
            await checkAuthWithValidation();
        } else {
            redirectToLogin();
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
        redirectToLogin();
    }
}
