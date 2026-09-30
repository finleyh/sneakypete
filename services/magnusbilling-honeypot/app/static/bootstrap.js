// Custom shim -- NOT copied from upstream MagnusBilling (see NOTICE.md).
//
// index.html's <script id="microloader" src="bootstrap.js"> is, in the real
// app, Sencha Cmd's ExtJS microloader: it pulls in the whole compiled
// single-page app that renders the actual login form. That microloader is a
// generated build artifact, not part of MagnusBilling's source repo, so
// there's nothing upstream to copy here.
//
// This replaces it with a minimal hand-written login form that matches the
// real app's visual boot state (same #loading-mask background color/theme
// already set by index.php's inline globals) and posts to the same
// index.php/authentication/login endpoint with the same request shape
// (username plus client-side-hashed password) that the real frontend uses.

(function () {
    function reportTiming(kind, data) {
        try {
            var body = JSON.stringify({ kind: kind, data: data });
            if (navigator.sendBeacon) {
                navigator.sendBeacon("index.php/telemetry", new Blob([body], { type: "application/json" }));
            } else {
                fetch("index.php/telemetry", { method: "POST", body: body, headers: { "Content-Type": "application/json" } }).catch(function () {});
            }
        } catch (e) {
            // best-effort only -- never let telemetry break the login flow
        }
    }

    function round(n) {
        return typeof n === "number" && isFinite(n) ? Math.round(n) : null;
    }

    // Connection-quality signal: how long the boot page actually took to
    // arrive and settle, broken down by phase, so slow-loading real assets
    // (init.css in particular) show up as a measurable number instead of a
    // vague "feels slow" impression.
    function reportPageLoadTiming() {
        var nav = performance.getEntriesByType && performance.getEntriesByType("navigation")[0];
        if (!nav) return;
        reportTiming("page_load", {
            dns_ms: round(nav.domainLookupEnd - nav.domainLookupStart),
            tcp_connect_ms: round(nav.connectEnd - nav.connectStart),
            ttfb_ms: round(nav.responseStart - nav.requestStart),
            html_download_ms: round(nav.responseEnd - nav.responseStart),
            dom_content_loaded_ms: round(nav.domContentLoadedEventEnd - nav.startTime),
            load_ms: round(nav.loadEventEnd - nav.startTime),
            transfer_size_bytes: nav.transferSize || null,
        });
    }

    function sha1Hex(text) {
        var data = new TextEncoder().encode(text);
        return crypto.subtle.digest("SHA-1", data).then(function (buf) {
            return Array.from(new Uint8Array(buf))
                .map(function (b) { return b.toString(16).padStart(2, "0"); })
                .join("")
                .toUpperCase();
        });
    }

    function showForm() {
        var mask = document.getElementById("loading-mask");
        var loading = document.getElementById("loading");
        if (mask) mask.style.display = "none";
        if (loading) loading.style.display = "none";

        var wrap = document.createElement("div");
        wrap.id = "login-wrap";
        wrap.innerHTML =
            '<div id="login-card">' +
            '<div id="login-title">MagnusBilling</div>' +
            '<div id="login-subtitle">Administrator Login</div>' +
            '<div id="login-error" style="display:none"></div>' +
            '<form id="login-form">' +
            '<input type="text" id="login-user" placeholder="Username" autocomplete="off">' +
            '<input type="password" id="login-password" placeholder="Password" autocomplete="off">' +
            '<button type="submit">Sign in</button>' +
            "</form>" +
            "</div>";
        document.body.appendChild(wrap);

        var style = document.createElement("style");
        style.textContent =
            "#login-wrap { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; background: " + (window.backgroundColor || "#0b1220") + "; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }" +
            "#login-card { width: 320px; background: #111a2c; border: 1px solid #22304a; border-radius: 6px; padding: 28px; box-shadow: 0 4px 16px rgba(0,0,0,0.4); }" +
            "#login-title { color: #e6ebf5; font-size: 20px; font-weight: 600; margin-bottom: 2px; }" +
            "#login-subtitle { color: #7d8aa3; font-size: 12px; margin-bottom: 18px; }" +
            "#login-error { background: #4a1f24; color: #f3a5ac; font-size: 12px; padding: 8px 10px; border-radius: 4px; margin-bottom: 14px; }" +
            "#login-form input { width: 100%; box-sizing: border-box; padding: 9px 10px; margin-bottom: 10px; background: #0b1220; border: 1px solid #22304a; border-radius: 4px; color: #e6ebf5; font-size: 13px; }" +
            "#login-form button { width: 100%; padding: 10px; margin-top: 4px; background: #2f6fed; color: #fff; border: none; border-radius: 4px; font-size: 13px; cursor: pointer; }" +
            "#login-form button:hover { background: #245bc7; }";
        document.head.appendChild(style);

        document.getElementById("login-form").addEventListener("submit", function (ev) {
            ev.preventDefault();
            var user = document.getElementById("login-user").value;
            var password = document.getElementById("login-password").value;
            var errorBox = document.getElementById("login-error");
            var requestStart = performance.now();

            sha1Hex(password).then(function (hashed) {
                var body = new URLSearchParams({ user: user, password: hashed, key: "" });
                return fetch("index.php/authentication/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/x-www-form-urlencoded" },
                    body: body.toString(),
                });
            }).then(function (resp) {
                var rttMs = round(performance.now() - requestStart);
                return resp.json().then(function (data) {
                    reportTiming("login_rtt", { rtt_ms: rttMs, http_status: resp.status });
                    return data;
                });
            }).then(function (data) {
                errorBox.textContent = data.msg || "Login failed";
                errorBox.style.display = "block";
            }).catch(function () {
                errorBox.textContent = "Unable to reach server";
                errorBox.style.display = "block";
            });
        });
    }

    setTimeout(showForm, 350);

    if (document.readyState === "complete") {
        reportPageLoadTiming();
    } else {
        window.addEventListener("load", function () {
            // Navigation timing entries (loadEventEnd in particular) aren't
            // final until just after the load event fires.
            setTimeout(reportPageLoadTiming, 0);
        });
    }
})();
