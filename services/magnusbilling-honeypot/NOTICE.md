# Third-party origin

`app/static/index.html` and `app/static/resources/init.css` are unmodified
copies of MagnusBilling's real application bootstrap page and its
stylesheet, taken from:

- Repo: https://github.com/magnussolution/magnusbilling
- Paths: `index.html`, `resources/init.css`
- Commit: `eae92c561ee3a8b4eefe2f3b3f455fb36f380959` (branch `source`)
- License: GNU Lesser General Public License v3.0 (see upstream `LICENSE`)

Not copied: `resources/images/*` (logo/wallpaper assets — trademark
concerns), `icons.js` (Sencha/Yii build artifact, not checked into the
source repo at all — generated at build time). Requests for those 404
through the catch-all route.

`app/static/locale.js` and `app/static/bootstrap.js` are also **not**
upstream copies — the real files are ExtJS/Sencha Cmd build outputs (the
actual compiled single-page app), not present in the source repo either,
so there's nothing to copy. `index.html` references both unconditionally
and throws before ever showing a usable form if they 404 (confirmed: a
plain fetch of the boot page left the loading spinner up forever with no
login fields, since an uncaught `t is not defined` in one of index.html's
inline `<script>` blocks aborts that block before name-system/loading-msg
even get set). These two files are minimal hand-written replacements: a
`t()` passthrough, and a small vanilla-JS login form (styled to match the
real app's dark boot theme) that posts to `index.php/authentication/login`
with the same request shape described below. They do not attempt to
replicate the real ExtJS application beyond that.

The `index.php/authentication/login` response shape in `app/main.py`
(`{"success": false, "msg": "Username and password combination is
invalid"}`) mirrors the invalid-login branch of
`protected/controllers/AuthenticationController.php::actionLogin()` in the
same repo, and the request shape (`user`, `password` as client-side
`SHA1(password)`, `key`) mirrors
`classic/src/view/main/LoginController.js::onLogin()`. Neither file is
copied verbatim; only the observed request/response contract is
reimplemented here, to make the decoy's login flow match what a real
MagnusBilling-aware client or scanner would see.
