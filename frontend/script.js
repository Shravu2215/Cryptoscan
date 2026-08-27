document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form');
  const API_URL = 'http://localhost:3000/api/auth';

  // Handle Form Submission
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const btn = loginForm.querySelector('.btn-primary');
    const originalText = btn.textContent;

    btn.textContent = 'LOGGING IN...';
    btn.disabled = true;

    try {
      const res = await fetch(`${API_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (data.success) {
        alert('Login Successful!');
        window.location.href = 'dashboard.html';
      } else {
        alert(data.message || 'Login failed');
      }
    } catch (err) {
      alert('Error connecting to server');
    } finally {
      btn.textContent = originalText;
      btn.disabled = false;
    }
  });

  // Check auth status on load
  async function checkAuth() {
    try {
      const res = await fetch(`${API_URL}/me`);
      if (res.ok) {
        // window.location.href = '/dashboard';
      }
    } catch (err) {}
  }
  
  checkAuth();
});
