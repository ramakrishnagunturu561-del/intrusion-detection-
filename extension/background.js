const API_BASE_URL = "http://127.0.0.1:8000";

let latestResult = null;
let captureRunning = false;

console.log("[UC029] Background service worker loaded");

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

    console.log("[UC029] Message received:", message);

    if (message.type === "START_CAPTURE") {

        if (captureRunning) {
            sendResponse({
                success: false,
                error: "Capture already running"
            });
            return true;
        }

        captureRunning = true;

        console.log("[UC029] Starting /capture-live...");

        fetch(
            `${API_BASE_URL}/capture-live`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify({
                    interface: "4",
                    duration: 5,
                    packet_count: null
                })
            }
        )
        .then(async response => {

            console.log(
                "[UC029] HTTP status:",
                response.status
            );

            const data = await response.json();

            console.log(
                "[UC029] CAPTURE RESULT:",
                data
            );

            if (!response.ok) {
                throw new Error(
                    data.detail || `HTTP ${response.status}`
                );
            }

            latestResult = data;

            await chrome.storage.local.set({
                uc029_latest_result: data
            });

            sendResponse({
                success: true,
                result: data
            });

        })
        .catch(error => {

            console.error("[UC029] CAPTURE ERROR OBJECT:", error);
            console.error("[UC029] ERROR NAME:", error?.name);
            console.error("[UC029] ERROR MESSAGE:", error?.message);
            console.error("[UC029] ERROR STACK:", error?.stack);

            sendResponse({
                success: false,
                error: error?.message || "Unknown capture error",
                error_name: error?.name || "UnknownError"
            });
        })
        .finally(() => {

            captureRunning = false;

            console.log(
                "[UC029] Capture finished"
            );
        });

        return true;
    }


    if (message.type === "GET_LATEST_RESULT") {

        chrome.storage.local.get(
            ["uc029_latest_result"],
            data => {

                sendResponse({
                    success: true,
                    result:
                        data.uc029_latest_result ||
                        null
                });
            }
        );

        return true;
    }
});