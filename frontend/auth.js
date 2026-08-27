/**
 * CryptoScan Auth Module
 * Handles JWT token storage, user session, and route protection.
 */

const AUTH_KEY = 'cs_auth_token';
const USER_KEY = 'cs_user';

const Auth = {
  /** Save token + user after login */
  saveSession(token, user) {
    localStorage.setItem(AUTH_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  },

  /** Get stored JWT */
  getToken() {
    return localStorage.getItem(AUTH_KEY);
  },

  /** Get stored user object */
  getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY));
    } catch {
      return null;
    }
  },

  /** True if a token exists (basic check) */
  isLoggedIn() {
    const token = this.getToken();
    if (!token) return false;
    // Decode expiry from JWT payload (no signature check needed client-side)
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        this.clearSession();
        return false;
      }
    } catch {}
    return true;
  },

  /** Clear session and redirect to login */
  clearSession() {
    localStorage.removeItem(AUTH_KEY);
    localStorage.removeItem(USER_KEY);
  },

  logout() {
    this.clearSession();
    window.location.href = 'login.html';
  },

  /**
   * Call this at the top of every protected page.
   * Redirects to login if not authenticated.
   */
  requireAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = 'login.html';
      return false;
    }
    return true;
  },

  /** Returns headers with Authorization for fetch calls */
  headers() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.getToken()}`
    };
  }
};
