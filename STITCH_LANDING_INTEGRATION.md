# Stitch Landing Page Integration

The exported Stitch landing page has been integrated into `frontend/index.html`.

## Flow
- `/` -> landing page
- `Start Scanning` -> `login.html`
- existing login -> existing authentication -> `dashboard.html`

## Preserved
- Existing `login.html`
- Existing `signup.html`
- Existing dashboard and application pages
- Existing backend/authentication logic

## Added interactions
- Sticky/compact navbar on scroll
- Scroll reveal animations
- Hero mouse tilt/parallax
- Animated ambient glow
- Feature/card hover states
- FAQ accordion
- Active desktop navigation state
- Responsive mobile navigation
- Escape-key handling
- Reduced-motion support

`frontend/index.login-backup.html` contains the previous homepage/login markup for rollback if needed.
