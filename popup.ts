// Get elements from popup
const checkBtn = document.getElementById("checkBtn");
const urlInput = document.getElementById("urlInput");
const resultDiv = document.getElementById("result");

// Your ML API endpoint (replace with your actual API endpoint)
const API_URL = "https://your-ml-api.com/predict"; // Example placeholder
const API_KEY = "AIzaSyB57h7CDpX5_mcZZXo_OXab12Y1eJQET6A";

// Event listener for button click
checkBtn.addEventListener("click", async () => {
  const url = urlInput.value.trim();
  if (!url) {
    resultDiv.textContent = "Please enter a URL.";
    resultDiv.style.color = "red";
    return;
  }

  resultDiv.textContent = "Checking...";
  resultDiv.style.color = "black";

  try {
    // Send URL to ML API
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${API_KEY}`
      },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();

    // Assuming API returns { prediction: "Safe"/"Not Safe", confidence: 0-100 }
    let status = data.prediction;
    const confidence = data.confidence;

    if (confidence < 70) {
      status = "Not Safe"; // Override if confidence < 70%
    }

    resultDiv.textContent = `${status} (${confidence.toFixed(2)}%)`;
    resultDiv.style.color = status === "Safe" ? "green" : "red";

  } catch (err) {
    resultDiv.textContent = `Error: ${err.message}`;
    resultDiv.style.color = "red";
  }
});
