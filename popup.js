// Load saved config
function loadSettings() {
    chrome.runtime.sendMessage({ action: "getConfig" }, function(resp) {
        document.getElementById("phishList").value = resp.cfg.phish.join("\n");
        document.getElementById("whiteList").value = resp.cfg.white.join("\n");
    });
}

// Save settings
document.getElementById("saveBtn").addEventListener("click", function() {
    var phish = document.getElementById("phishList").value.split("\n").map(s => s.trim()).filter(Boolean);
    var white = document.getElementById("whiteList").value.split("\n").map(s => s.trim()).filter(Boolean);
    chrome.runtime.sendMessage({ action: "saveConfig", payload: { phish: phish, white: white } }, function(resp) {
        alert("Settings saved!");
    });
});

// Refresh button
document.getElementById("refreshBtn").addEventListener("click", function() {
    loadSettings();
});

// Manual check
document.getElementById("checkBtn").addEventListener("click", function() {
    var url = document.getElementById("manualUrl").value.trim();
    if (!url) return alert("Enter a URL");
    chrome.runtime.sendMessage({ action: "manualCheck", url: url }, function(resp) {
        document.getElementById("checkResult").innerText = resp.suspicious ? "Phishing! Reason: " + resp.reason : "Safe";
    });
});

loadSettings();