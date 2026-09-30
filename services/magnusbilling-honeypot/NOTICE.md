# Third-party origin

`app/static/index.html` and `app/static/resources/init.css` are unmodified
copies of MagnusBilling's real application bootstrap page and its
stylesheet, taken from:

- Repo: https://github.com/magnussolution/magnusbilling
- Paths: `index.html`, `resources/init.css`
- Commit: `eae92c561ee3a8b4eefe2f3b3f455fb36f380959` (branch `source`)
- License: GNU Lesser General Public License v3.0 (see upstream `LICENSE`)

Not copied: `resources/images/*` (logo/wallpaper assets — trademark
concerns), `locale.js`, `icons.js`, `bootstrap.js` (Sencha/Yii build
artifacts, not checked into the source repo at all — generated at build
time). Requests for those 404 through the catch-all route.

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
