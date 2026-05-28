// ==========================
// FILTER TABLE
// ==========================
let selectedSeverity = "ALL";
let selectedType = "ALL";

function filterTable(level) {
    selectedSeverity = level;
    applyFilters();
}

function filterByType(type) {
    selectedType = type;
    applyFilters();
}

function applyFilters() {
    const rows = document.querySelectorAll("#tableBody tr");

    rows.forEach(row => {
        const matchesSeverity = selectedSeverity === "ALL" || row.dataset.severity === selectedSeverity;
        const matchesType = selectedType === "ALL" || row.dataset.type === selectedType;

        row.style.display = matchesSeverity && matchesType ? "" : "none";
    });
}

function populateTypeFilter(data) {
    const dropdown = document.getElementById("typeFilter");
    const existingSelection = dropdown.value || "ALL";
    const types = [...new Set(data.map(item => item.type).filter(Boolean))].sort();

    dropdown.innerHTML = '<option value="ALL">All Types</option>';

    types.forEach(type => {
        const option = document.createElement("option");
        option.value = type;
        option.text = type;
        dropdown.appendChild(option);
    });

    dropdown.value = types.includes(existingSelection) ? existingSelection : "ALL";
    selectedType = dropdown.value;
    applyFilters();
}


// ==========================
// RUN SCAN (MAIN ACTION)
// ==========================
function runScan() {
    const loader = document.getElementById("loader");
    loader.style.display = "block";

    fetch("/run_scan", { method: "POST" })
        .then(res => res.json())
        .then(response => {
            const data = response.data;

            updateTable(data);
            updateMetrics(data);
            updateChart(data);
            updateDropdown(response.all_reports);
            populateTypeFilter(data);
            updateLastScan();

            alert("Scan complete!");
        })
        .catch(err => {
            console.error("Scan failed:", err);
            alert("Scan failed. Check backend.");
        })
        .finally(() => {
            loader.style.display = "none";
        });
}


// ==========================
// UPDATE DROPDOWN
// ==========================
function updateDropdown(reports) {
    const dropdown = document.getElementById("reportDropdown");
    dropdown.innerHTML = "";

    reports.forEach(file => {
        const option = document.createElement("option");
        option.value = file;

        option.text = file
            .replace("report_", "")
            .replace(".json", "")
            .replace("_", " ");

        dropdown.appendChild(option);
    });

    // select latest automatically
    if (reports.length > 0) {
        dropdown.value = reports[0];
    }
}


// ==========================
// UPDATE TABLE
// ==========================
function updateTable(data) {
    const table = document.getElementById("tableBody");
    table.innerHTML = "";

    data.forEach(item => {
        const row = `
            <tr data-severity="${item.severity}" data-type="${item.type}" data-resource="${item.resource}" data-issue="${item.issue}" data-impact="${item.impact || ''}">
                <td>${item.resource}</td>
                <td>${item.type}</td>
                <td>
                    ${item.issue}
                    <button class="explain-btn" onclick="onExplain(this)">Explain</button>
                </td>
                <td class="impact-cell">${item.impact || "N/A"}</td>
                <td>
                    <span class="badge ${item.severity.toLowerCase()}">
                        ${item.severity}
                    </span>
                </td>
            </tr>
        `;
        table.innerHTML += row;
    });

    applyFilters();
}


// ==========================
// EXPLAIN / AI
// ==========================
function onExplain(btn) {
    const tr = btn.closest('tr');
    const payload = {
        resource: tr.dataset.resource,
        type: tr.dataset.type,
        issue: tr.dataset.issue,
        severity: tr.dataset.severity,
        impact: tr.dataset.impact
    };
    showExplain('Loading...');

    fetch('/explain_finding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) showExplain('Error: ' + data.error);
        else showExplain(data);
    })
    .catch(err => showExplain('Request failed: ' + err));
}

function showExplain(content) {
    const modal = document.getElementById('explainModal');
    const body = document.getElementById('explainBody');

    try {
        let parsed = null;

        if (content && typeof content === 'object') {
            parsed = content;
        } else if (typeof content === 'string') {
            let cleaned = content.trim();

            if (cleaned.startsWith('```json')) {
                cleaned = cleaned.replace(/^```json\s*\n?/, '').replace(/\n?```\s*$/, '');
            } else if (cleaned.startsWith('```')) {
                cleaned = cleaned.replace(/^```\s*\n?/, '').replace(/\n?```\s*$/, '');
            }

            const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
            if (jsonMatch) cleaned = jsonMatch[0];

            try {
                parsed = JSON.parse(cleaned);
            } catch (e) {
                // not JSON — leave parsed null and fall back to text
            }
        }

        if (parsed && typeof parsed === 'object' && parsed.explanation) {
            const escapeHtml = (value) => String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');

            let remediationHtml = '';

            if (Array.isArray(parsed.remediation) && parsed.remediation.length > 0) {
                remediationHtml = `
                    <h3>Remediation Steps</h3>
                    <ol>
                        ${parsed.remediation.map(step => `<li>${escapeHtml(step)}</li>`).join('')}
                    </ol>
                `;
            }

            const formattedHtml = `
                <div class="explain-content">
                    <h3>Explanation</h3>
                    <p>${escapeHtml(parsed.explanation)}</p>
                    ${remediationHtml}
                </div>
            `;
            body.innerHTML = formattedHtml;
            modal.style.display = 'flex';
            return;
        }
    } catch (e) {
        console.error('showExplain error', e);
    }

    // Fallback: display as plain text if JSON parsing fails
    body.innerText = typeof content === 'string' ? content : JSON.stringify(content, null, 2);
    modal.style.display = 'flex';
}

function closeExplain() {
    const modal = document.getElementById('explainModal');
    modal.style.display = 'none';
}


// ==========================
// UPDATE METRICS
// ==========================
function updateMetrics(data) {
    let critical = 0, high = 0, medium = 0;

    data.forEach(item => {
        if (item.severity === "CRITICAL") critical++;
        else if (item.severity === "HIGH") high++;
        else if (item.severity === "MEDIUM") medium++;
    });

    document.getElementById("criticalCount").innerText = critical;
    document.getElementById("highCount").innerText = high;
    document.getElementById("mediumCount").innerText = medium;
}


// ==========================
// UPDATE CHART
// ==========================
function updateChart(data) {
    let counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };

    data.forEach(item => {
        counts[item.severity]++;
    });

    chart.data.datasets[0].data = [
        counts.CRITICAL,
        counts.HIGH,
        counts.MEDIUM
    ];

    chart.update();
}


// ==========================
// LAST SCAN TIME
// ==========================
function updateLastScan() {
    fetch("/last_scan")
        .then(res => res.json())
        .then(data => {
            if (!data.last_scan) {
                document.getElementById("lastScan").innerText =
                    "Last scan: No scans yet";
                return;
            }

            const last = new Date(data.last_scan);
            const now = new Date();

            const diff = Math.floor((now - last) / 60000);

            document.getElementById("lastScan").innerText =
                diff <= 0
                    ? "Last scan: Just now"
                    : `Last scan: ${diff} min ago`;
        })
        .catch(() => {
            document.getElementById("lastScan").innerText =
                "Last scan: unavailable";
        });
}


// ==========================
// AUTO REFRESH LAST SCAN
// ==========================
setInterval(updateLastScan, 10000);
updateLastScan();


// ==========================
// THEME (DARK MODE)
// ==========================
function toggleTheme() {
    const isDark = document.body.classList.toggle('dark');
    try { localStorage.setItem('theme', isDark ? 'dark' : 'light'); } catch(e) {}
    const btn = document.getElementById('themeToggle');
    if (btn) btn.textContent = isDark ? '☀️' : '🌙';
}

function initTheme() {
    try {
        const saved = localStorage.getItem('theme');
        if (saved === 'dark') document.body.classList.add('dark');
    } catch(e) {}
    const btn = document.getElementById('themeToggle');
    if (btn) btn.textContent = document.body.classList.contains('dark') ? '☀️' : '🌙';
}