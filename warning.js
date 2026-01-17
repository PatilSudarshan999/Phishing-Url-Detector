// warning.js — CSP-safe, used in warning.html
(function() {
    // Helper to get query params
    function qs(param) {
        try {
            const u = new URL(location.href);
            return u.searchParams.get(param);
        } catch (e) {
            return null;
        }
    }

    // Detect local/private IPs
    function isLocalOrPrivate(url) {
        try {
            const u = new URL(url);
            const h = u.hostname;

            if (h === "localhost") return true;
            if (h === "127.0.0.1") return true;
            if (h.startsWith("192.168.")) return true;
            if (h.startsWith("10.")) return true;
            if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(h)) return true;

            return false;
        } catch (e) {
            return false;
        }
    }

    // -------- Parse URL params --------
    var orig = qs("orig") ? decodeURIComponent(qs("orig")) : "";
    var domain = qs("d") ? decodeURIComponent(qs("d")) : "";
    var reason = qs("r") ? decodeURIComponent(qs("r")) : "";
    var confidence = qs("c") || "";

    var origEl = document.getElementById("orig");
    var metaEl = document.getElementById("meta");
    var reasonEl = document.getElementById("reason");
    var confidenceEl = document.getElementById("confidence");

    if (origEl) origEl.textContent = orig || "unknown";

    // -------- LOCAL / PRIVATE URL BYPASS --------
    if (orig && isLocalOrPrivate(orig)) {
        if (metaEl) {
            metaEl.textContent = "Local/private network address detected. Phishing checks skipped.";
        }
        if (reasonEl) reasonEl.textContent = "Local / Private IP";
        if (confidenceEl) confidenceEl.textContent = "N/A";

        var openBtnLocal = document.getElementById("open");
        if (openBtnLocal) openBtnLocal.addEventListener("click", function() {
            location.href = orig;
        });

        var backBtnLocal = document.getElementById("back");
        if (backBtnLocal) backBtnLocal.addEventListener("click", function() {
            location.href = "about:blank";
        });

        var reportBtnLocal = document.getElementById("report");
        if (reportBtnLocal) reportBtnLocal.addEventListener("click", function() {
            alert("Local URLs are always treated as safe.");
        });

        return; // stop here
    }

    // -------- NORMAL WARNING --------
    if (metaEl) {
        metaEl.textContent = "Domain: " + domain;
    }
    if (reasonEl) reasonEl.textContent = reason || "Unknown";
    if (confidenceEl) confidenceEl.textContent = confidence || "N/A";

    // -------- BUTTON HANDLERS --------
    var backBtn = document.getElementById("back");
    if (backBtn) {
        backBtn.addEventListener("click", function() {
            try {
                chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
                    if (tabs && tabs[0] && typeof tabs[0].id === "number") {
                        chrome.tabs.remove(tabs[0].id);
                    } else {
                        location.href = "about:blank";
                    }
                });
            } catch (e) {
                location.href = "about:blank";
            }
        });
    }

    var openBtn = document.getElementById("open");
    if (openBtn) {
        openBtn.addEventListener("click", function() {
            if (!orig) return;
            try {
                chrome.runtime.sendMessage({ action: "bypassOnce", url: orig }, function() {
                    location.href = orig;
                });
            } catch (e) {
                location.href = orig;
            }
        });
    }

    var reportBtn = document.getElementById("report");
    if (reportBtn) {
        reportBtn.addEventListener("click", function() {
            if (!domain) {
                alert("No domain to whitelist.");
                return;
            }
            try {
                chrome.runtime.sendMessage({ action: "saveConfig", payload: { white: [domain] } }, function(resp) {
                    if (resp && resp.ok) {
                        alert("Domain " + domain + " added to whitelist.");
                    } else {
                        alert("Failed to add domain to whitelist.");
                    }
                });
            } catch (e) {
                alert("Error adding to whitelist: " + e);
            }
        });
    }
})();