const API_BASE_URL = "http://127.0.0.1:8000";
const CAPTURE_DURATION = 5;

document.addEventListener("DOMContentLoaded", async () => {

    const startBtn = document.getElementById("start-capture-btn");
    const refreshBtn = document.getElementById("refresh-btn");

    const backendPill =
        document.getElementById("backend-status-pill");

    const backendText =
        document.getElementById("backend-status-text");

    const domainDisplay =
        document.getElementById("active-domain-display");

    const totalFlows =
        document.getElementById("stat-total-flows");

    const benignFlows =
        document.getElementById("stat-benign-flows");

    const suspiciousFlows =
        document.getElementById("stat-suspicious-flows");

    const attackFlows =
        document.getElementById("stat-attack-flows");

    const riskCard =
        document.getElementById("risk-summary-card");

    const riskBadge =
        document.getElementById("risk-level-badge");

    const riskPrediction =
        document.getElementById("risk-prediction-text");

    const captureInfo =
        document.getElementById("capture-info-text");

    const flowTable =
        document.getElementById("flow-table-body");

    const flowCount =
        document.getElementById("flow-count-tag");

    const errorBox =
        document.getElementById("error-alert-box");

    const errorMessage =
        document.getElementById("error-alert-message");


    // ========================================================
    // ERROR
    // ========================================================

    function showError(message) {

        errorMessage.textContent =
            String(message);

        errorBox.classList.remove("hidden");
    }


    function hideError() {

        errorBox.classList.add("hidden");
    }


    // ========================================================
    // CURRENT TAB
    // ========================================================

    async function getCurrentDomain() {

        try {

            const tabs =
                await chrome.tabs.query({
                    active: true,
                    currentWindow: true
                });

            if (
                tabs.length > 0 &&
                tabs[0].url
            ) {

                const url =
                    new URL(tabs[0].url);

                domainDisplay.textContent =
                    url.hostname;

            } else {

                domainDisplay.textContent =
                    "Unknown";
            }

        } catch (error) {

            domainDisplay.textContent =
                "Unknown";
        }
    }


    // ========================================================
    // HEALTH
    // ========================================================

    async function checkHealth() {

        backendText.textContent =
            "Checking...";

        backendPill.className =
            "status-pill status-checking";

        try {

            const response =
                await fetch(
                    `${API_BASE_URL}/health`
                );

            if (!response.ok) {
                throw new Error(
                    `HTTP ${response.status}`
                );
            }

            const data =
                await response.json();

            backendText.textContent =
                "Backend Online";

            backendPill.className =
                "status-pill status-online";

            return data;

        } catch (error) {

            backendText.textContent =
                "Backend Offline";

            backendPill.className =
                "status-pill status-offline";

            throw error;
        }
    }


    // ========================================================
    // LIVE CAPTURE
    // ========================================================

    async function startCapture() {

        if (startBtn.disabled) {
            return;
        }

        hideError();

        startBtn.disabled = true;

        startBtn.textContent =
            "⏳ Capturing...";


        try {

            console.log(
                "[UC029] Starting capture"
            );


            // First check backend

            await checkHealth();


            // Call backend directly

            console.log(
                "[UC029] POST /capture-live"
            );


            const response =
                await fetch(
                    `${API_BASE_URL}/capture-live`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",

                            "Accept":
                                "application/json"
                        },

                        body: JSON.stringify({
                            interface: "4",
                            duration:
                                CAPTURE_DURATION,
                            packet_count: null
                        })
                    }
                );


            console.log(
                "[UC029] HTTP:",
                response.status
            );


            // Read response as text first.
            // This makes debugging much easier.

            const rawText =
                await response.text();


            console.log(
                "[UC029] RAW RESPONSE:",
                rawText
            );


            if (!response.ok) {

                throw new Error(
                    `Backend returned HTTP ${
                        response.status
                    }: ${rawText}`
                );
            }


            let data;

            try {

                data =
                    JSON.parse(rawText);

            } catch (error) {

                throw new Error(
                    "Backend returned invalid JSON: " +
                    rawText
                );
            }


            console.log(
                "[UC029] CAPTURE DATA:",
                data
            );


            if (!data.success) {

                throw new Error(
                    data.error ||
                    data.detail ||
                    "Capture failed"
                );
            }


            // Render result

            renderResults(data);


        } catch (error) {

            console.error(
                "[UC029] CAPTURE ERROR:",
                error
            );

            showError(
                error.message ||
                "Capture failed"
            );

        } finally {

            startBtn.disabled = false;

            startBtn.textContent =
                "▶ Start Monitoring";
        }
    }


    // ========================================================
    // RENDER RESULTS
    // ========================================================

    function renderResults(data) {

        console.log(
            "[UC029] Rendering results"
        );


        const total =
            Number(
                data.total_flows_analyzed || 0
            );

        const benign =
            Number(
                data.benign_flows_detected || 0
            );

        const suspicious =
            Number(
                data.suspicious_flows_detected || 0
            );

        const attacks =
            Number(
                data.attack_flows_detected || 0
            );


        totalFlows.textContent =
            total;

        benignFlows.textContent =
            benign;

        suspiciousFlows.textContent =
            suspicious;

        attackFlows.textContent =
            attacks;


        const prediction =
            data.overall_prediction ||
            "BENIGN";

        const risk =
            data.overall_risk_level ||
            "LOW";


        riskCard.className =
            "risk-card";

        riskBadge.className =
            "risk-badge";


        if (risk === "HIGH") {

            riskCard.classList.add(
                "risk-attack"
            );

            riskBadge.classList.add(
                "badge-high"
            );

            riskBadge.textContent =
                "HIGH RISK";

            riskPrediction.textContent =
                "🔴 THREAT DETECTED";

        } else if (
            risk === "MEDIUM"
        ) {

            riskCard.classList.add(
                "risk-suspicious"
            );

            riskBadge.classList.add(
                "badge-medium"
            );

            riskBadge.textContent =
                "MEDIUM RISK";

            riskPrediction.textContent =
                "🟡 SUSPICIOUS ACTIVITY";

        } else {

            riskCard.classList.add(
                "risk-benign"
            );

            riskBadge.classList.add(
                "badge-low"
            );

            riskBadge.textContent =
                "LOW RISK";

            riskPrediction.textContent =
                "🟢 NETWORK BENIGN";
        }


        captureInfo.textContent =
            `Interface: ${
                data.interface_used || "4"
            } | Capture: ${
                data.actual_capture_time_sec || "-"
            }s`;


        const flows =
            Array.isArray(data.flows)
                ? data.flows
                : [];


        flowCount.textContent =
            `${flows.length} Flow${
                flows.length === 1
                    ? ""
                    : "s"
            }`;


        if (flows.length === 0) {

            flowTable.innerHTML = `
                <tr>
                    <td colspan="8">
                        No flows captured.
                    </td>
                </tr>
            `;

            return;
        }


        flowTable.innerHTML =
            flows.map(flow => {

                let badge =
                    "tbl-benign";

                if (
                    flow.final_prediction ===
                    "ATTACK"
                ) {

                    badge =
                        "tbl-attack";

                } else if (
                    flow.final_prediction ===
                    "SUSPICIOUS"
                ) {

                    badge =
                        "tbl-suspicious";
                }


                return `
                    <tr>

                        <td>
                            <strong>
                                ${safe(flow.flow_id)}
                            </strong>
                        </td>

                        <td>
                            ${safe(flow.src_ip)}
                        </td>

                        <td>
                            ${safe(flow.dst_ip)}
                        </td>

                        <td>
                            ${safe(flow.protocol)}
                        </td>

                        <td>
                            ${safe(
                                flow.classical_prediction
                            )}
                        </td>

                        <td>
                            ${safe(
                                flow.quantum_prediction
                            )}
                        </td>

                        <td>
                            <span class="tbl-badge ${badge}">
                                ${safe(
                                    flow.final_prediction
                                )}
                            </span>
                        </td>

                        <td>
                            ${safe(
                                flow.risk_level
                            )}
                        </td>

                    </tr>
                `;

            }).join("");
    }


    // ========================================================
    // HTML SAFETY
    // ========================================================

    function safe(value) {

        if (
            value === null ||
            value === undefined
        ) {

            return "";
        }

        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    // ========================================================
    // BUTTONS
    // ========================================================

    startBtn.addEventListener(
        "click",
        startCapture
    );


    refreshBtn.addEventListener(
        "click",
        async () => {

            hideError();

            await getCurrentDomain();

            try {

                await checkHealth();

            } catch (error) {

                showError(
                    "Backend is not reachable."
                );
            }
        }
    );


    // ========================================================
    // INITIAL LOAD
    // ========================================================

    await getCurrentDomain();

    try {

        await checkHealth();

    } catch (error) {

        showError(
            "Start FastAPI on port 8080."
        );
    }

});