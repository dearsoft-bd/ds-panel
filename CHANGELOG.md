# Changelog

## 2026-09-30

- **Security fix**: role/permission/site-scope changes made by a Super
  Admin now apply to an already-logged-in session on its very next
  request, instead of only after that account logs out and back in.
  Previously, a session that was already open before a Super Admin
  restricted it to a specific site kept its old, unrestricted access
  until it logged out — meaning a site-restricted Admin could see every
  site and every site's files, not just its own.
- Fixed: a site-restricted Admin whose site restriction data didn't
  resolve to a real, still-existing site now sees no sites/files (fails
  closed) instead of the entire server's site list (was failing open).
- Fixed: static assets (CSS/JS/images) were being blocked for
  site-restricted Admin accounts, breaking the entire panel UI for that
  role.
- DS-Panel now shows its own product logo (sidebar + login screen)
  instead of the DearSoft company logo.
- About Us page rebuilt to mirror dearsoft.com.bd/founder — company
  products, DS-Pythone, SEO Toolkit, ERP modules, and how we work.
- The "(restricted)" label is no longer shown next to a site-restricted
  admin's role in the topbar.
- Styled the "Also from DearSoft" cross-promo strip with per-product
  colored icons instead of flat grey pills.
- Fixed several About page call-to-action buttons ("Move my store to
  DS-Pythone", "Editions & pricing", "See ERP details & plans") that
  rendered as invisible white-on-white text on the page's light
  background.
