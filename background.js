// ----------------- CONFIG -----------------
const DEFAULT_PHISHING = [
    "bad-example.com",
    "phishingsite.xyz",
    "paypa1.com",
    "goog1e.com",
    "accounts-google.com",
    "secure-facebook-login.net",
    "login-paypal-secure.com",
    "verify-google-account.net",
    "facebook-login-alert.com",
    "appleid-verify-security.com",
    "bankofamerica-secure-login.net",
    "microsoft-account-check.com",
    "amazon-verify-payment.net",
    "update-instagram-security.com",
    "netflix-account-suspended.com"
];


const DEFAULT_WHITELIST = [
    "example.com",
    "mybank.com",
    "google.com",
    "github.com",
    "openai.com"
];

// Gemini API
const GEMINI_API_ENDPOINT = "https://gemini.googleapis.com/v1/phishing-detect";
const GEMINI_API_KEY = "AIzaSyBYrHAbRzYFUN_IA_8MZrJO97aPczh1zuc";

const KEY_PHISH = "phish_list";
const KEY_WHITE = "whitelist";
const bypassed = new Set();

// ----------------- UTILS -----------------
function getHost(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch (e) { return null; }
}

function loadConfig(callback) {
    chrome.storage.local.get([KEY_PHISH, KEY_WHITE], function(items) {
        const phish = Array.isArray(items[KEY_PHISH]) ? items[KEY_PHISH] : DEFAULT_PHISHING;
        const white = Array.isArray(items[KEY_WHITE]) ? items[KEY_WHITE] : DEFAULT_WHITELIST;
        callback({ phish: phish, white: white });
    });
}

function checkLocal(host, list) {
    if (!host) return false;
    host = host.toLowerCase();
    for (var i = 0; i < list.length; i++) {
        var pattern = new RegExp("(^|\\.)" + list[i].toLowerCase().replace(/\./g, "\\.") + "$");
        if (pattern.test(host)) return true;
    }
    return false;
}

function notify(title, message) {
    chrome.notifications.create("" + Date.now(), {
        type: "basic",
        iconUrl: "icon.png",
        title: title,
        message: message,
        priority: 2
    });
}

function redirectWarning(tabId, url, domain, reason, score) {
    var q = "?orig=" + encodeURIComponent(url) + "&d=" + encodeURIComponent(domain) + "&r=" + encodeURIComponent(reason);
    if (score !== null && score !== undefined) q += "&s=" + encodeURIComponent(score);
    var warningUrl = chrome.runtime.getURL("warning.html") + q;
    try { chrome.tabs.update(tabId, { url: warningUrl, active: true }); } catch (e) { console.warn("redirect error", e); }
}

// ----------------- GEMINI ML API -----------------
function callMlApi(url, callback) {
    try {
        fetch(GEMINI_API_ENDPOINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "x-api-key": GEMINI_API_KEY
            },
            body: JSON.stringify({ url: url })
        }).then(function(resp) {
            if (!resp.ok) { callback({ ok: false, reason: "http_error", status: resp.status }); return; }
            resp.json().then(function(data) { callback({ ok: true, result: data }); }).catch(function() { callback({ ok: false, reason: "json_error" }); });
        }).catch(function(err) { callback({ ok: false, reason: "network_error", error: String(err) }); });
    } catch (e) { callback({ ok: false, reason: "exception", error: String(e) }); }
}

// ----------------- NAVIGATION LISTENER -----------------
chrome.webNavigation.onBeforeNavigate.addListener(function(details) {
    var url = details.url;
    var tabId = details.tabId;
    var frameId = details.frameId;
    if (!url || tabId < 0 || frameId !== 0) return;

    var host = getHost(url);
    loadConfig(function(cfg) {
        if (!host || bypassed.has(host) || checkLocal(host, cfg.white)) return;

        // Check with Gemini API
        callMlApi(url, function(ml) {
            var flagged = false;
            var reason = "";
            var score = null;

            if (ml.ok && ml.result && ml.result.suspicious) {
                flagged = true;
                reason = "ml_flag";
                score = ml.result.score !== undefined ? ml.result.score : null;
            } else if (checkLocal(host, cfg.phish)) {
                flagged = true;
                reason = "local_list";
            }

            if (flagged) {
                notify("Suspicious Site Detected", "Navigation to " + host + " flagged as " + reason + (score !== null ? " (score " + score + ")" : ""));
                redirectWarning(tabId, url, host, reason, score);
            }
        });
    });
});

// ----------------- MESSAGE LISTENER -----------------
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
    if (msg.action === "getConfig") {
        loadConfig(function(cfg) { sendResponse({ cfg: cfg }); });
        return true;
    }
    if (msg.action === "saveConfig") {
        chrome.storage.local.set({ phish_list: msg.payload.phish, whitelist: msg.payload.white }, function() { sendResponse({ ok: true }); });
        return true;
    }
    if (msg.action === "manualCheck") {
        var url = msg.url;
        var host = getHost(url);
        loadConfig(function(cfg) {
            callMlApi(url, function(ml) {
                var flagged = false;
                var reason = "";
                var score = null;

                if (ml.ok && ml.result && ml.result.suspicious) {
                    flagged = true;
                    reason = "ml_flag";
                    score = ml.result.score !== undefined ? ml.result.score : null;
                } else if (checkLocal(host, cfg.phish)) {
                    flagged = true;
                    reason = "local_list";
                }

                sendResponse({ suspicious: flagged, reason: reason, score: score });
            });
        });
        return true;
    }
}); // ================= GEMINI CONFIG =================

// ================= GEMINI CONFIG =================

// ================= CONFIG =================

// // Gemini API key (optional, for explanation)
// var GEMINI_API_KEY = "AIzaSyBYrHAbRzYFUN_IA_8MZrJO97aPczh1zuc";
// var GEMINI_ENDPOINT =
//     "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" +
//     GEMINI_API_KEY;

// // Google Safe Browsing API key (mandatory)
// var SAFEBROWSING_API_KEY = "AIzaSyDHKilcbLxAKJeIOMHiKxvadv2njBXZIBI";
// var SAFEBROWSING_ENDPOINT =
//     "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
//     SAFEBROWSING_API_KEY;

// // ================= LOCAL LISTS =================
// var DEFAULT_PHISHING = [
//     "paypa1.com",
//     "goog1e.com",
//     "secure-facebook-login.net"
// ];
// var DEFAULT_WHITELIST = [
//     "google.com",
//     "github.com",
//     "openai.com",
//     "wikipedia.org"
// ];

// var KEY_PHISH = "phish_list";
// var KEY_WHITE = "whitelist";

// // ================= UTILS =================
// function getHost(url) {
//     try {
//         return new URL(url).hostname.toLowerCase();
//     } catch (e) {
//         return null;
//     }
// }

// function isPrivateHost(host) {
//     if (!host) return true;
//     return (
//         host === "localhost" ||
//         host === "127.0.0.1" ||
//         host.indexOf("192.168.") === 0 ||
//         host.indexOf("10.") === 0 ||
//         /^172\.(1[6-9]|2\d|3[0-1])\./.test(host)
//     );
// }

// function checkLocal(host, list) {
//     for (var i = 0; i < list.length; i++) {
//         if (host === list[i] || host.indexOf("." + list[i]) !== -1) {
//             return true;
//         }
//     }
//     return false;
// }

// function loadConfig(cb) {
//     chrome.storage.local.get([KEY_PHISH, KEY_WHITE], function(items) {
//         cb({
//             phish: Array.isArray(items[KEY_PHISH]) ? items[KEY_PHISH] : DEFAULT_PHISHING,
//             white: Array.isArray(items[KEY_WHITE]) ? items[KEY_WHITE] : DEFAULT_WHITELIST
//         });
//     });
// }

// function notify(title, message) {
//     chrome.notifications.create({
//         type: "basic",
//         iconUrl: "icon.png",
//         title: title,
//         message: message
//     });
// }

// function redirectWarning(tabId, url, domain, reason, confidence) {
//     var q =
//         "?orig=" + encodeURIComponent(url) +
//         "&d=" + encodeURIComponent(domain) +
//         "&r=" + encodeURIComponent(reason) +
//         "&c=" + encodeURIComponent(confidence);

//     chrome.tabs.update(tabId, {
//         url: chrome.runtime.getURL("warning.html") + q
//     });
// }

// // ================= SAFE BROWSING CHECK =================
// function checkSafeBrowsing(url, callback) {
//     fetch(SAFEBROWSING_ENDPOINT, {
//             method: "POST",
//             headers: { "Content-Type": "application/json" },
//             body: JSON.stringify({
//                 client: { clientId: "phishing-detector", clientVersion: "1.0" },
//                 threatInfo: {
//                     threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
//                     platformTypes: ["ANY_PLATFORM"],
//                     threatEntryTypes: ["URL"],
//                     threatEntries: [{ url }]
//                 }
//             })
//         })
//         .then(r => r.json())
//         .then(data => callback(!!data.matches))
//         .catch(() => callback(false));
// }

// // ================= GEMINI EXPLANATION (optional) =================
// function getGeminiExplanation(url, callback) {
//     if (!GEMINI_API_KEY) return callback("AI explanation not available");
//     var prompt =
//         "You are a cybersecurity system.\nAnalyze this URL and explain why it might be phishing:\n" + url;
//     fetch(GEMINI_ENDPOINT, {
//             method: "POST",
//             headers: { "Content-Type": "application/json" },
//             body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
//         })
//         .then(r => r.json())
//         .then(data => {
//             try {
//                 var text = data.candidates[0].content.parts[0].text || "AI explanation not available";
//                 callback(text);
//             } catch (e) {
//                 callback("AI explanation error");
//             }
//         })
//         .catch(() => callback("AI explanation error"));
// }

// // ================= NAVIGATION LISTENER =================
// chrome.webNavigation.onBeforeNavigate.addListener(details => {
//     if (details.frameId !== 0) return;

//     var url = details.url;
//     var tabId = details.tabId;
//     var host = getHost(url);
//     if (!host || isPrivateHost(host)) return;

//     loadConfig(cfg => {
//         // WHITELIST
//         if (checkLocal(host, cfg.white)) return;

//         // LOCAL BLACKLIST
//         if (checkLocal(host, cfg.phish)) {
//             notify("Phishing Blocked", host + " is blacklisted");
//             redirectWarning(tabId, url, host, "local_list", 1.0);
//             return;
//         }

//         // SAFE BROWSING CHECK
//         checkSafeBrowsing(url, isUnsafe => {
//             if (isUnsafe) {
//                 getGeminiExplanation(url, explanation => {
//                     notify("⚠️ Phishing Detected", host + " • " + explanation);
//                     redirectWarning(tabId, url, host, "safebrowsing", 1.0);
//                 });
//             }
//         });
//     });
// });

// // ================= MESSAGE HANDLER =================
// chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
//     if (msg.action === "manualCheck") {
//         checkSafeBrowsing(msg.url, isUnsafe => {
//             if (isUnsafe) {
//                 getGeminiExplanation(msg.url, explanation => {
//                     sendResponse({ suspicious: true, reason: explanation });
//                 });
//             } else {
//                 sendResponse({ suspicious: false });
//             }
//         });
//         return true;
//     }
// });