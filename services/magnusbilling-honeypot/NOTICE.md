# Third-party origin

`app/static/index.html` is an unmodified copy of MagnusBilling's real
application bootstrap page, taken from:

- Repo: https://github.com/magnussolution/magnusbilling
- Path: `index.html`
- Commit: `eae92c561ee3a8b4eefe2f3b3f455fb36f380959` (branch `source`)
- License: GNU Lesser General Public License v3.0 (see upstream `LICENSE`)

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
