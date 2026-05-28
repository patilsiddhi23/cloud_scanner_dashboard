from flask import Flask, render_template, request, send_file, jsonify
import json
import os
from datetime import datetime, timezone
from scanner import run_scan as aws_run_scan  # avoid name conflict
import requests

# AI / Gemini config via environment
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
GEMINI_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')

app = Flask(__name__)

REPORTS_FOLDER = "reports"


# -------------------------
# Helpers
# -------------------------

def get_all_reports():
    if not os.path.exists(REPORTS_FOLDER):
        return []

    files = [f for f in os.listdir(REPORTS_FOLDER) if f.endswith(".json")]
    files.sort(reverse=True)  # latest first
    return files


def load_report(filename):
    path = os.path.join(REPORTS_FOLDER, filename)
    if not os.path.exists(path):
        return []

    with open(path) as f:
        return json.load(f)


def format_timestamp(filename):
    try:
        name = filename.replace("report_", "").replace(".json", "")
        return name.replace("_", " ")
    except:
        return filename


def get_latest_report_time():
    reports = get_all_reports()
    if not reports:
        return None

    latest = reports[0]
    timestamp = latest.replace("report_", "").replace(".json", "")

    try:
        # NEW FORMAT WITH SECONDS
        return datetime.strptime(timestamp, "%Y-%m-%d_%H-%M-%S")
    except:
        return None



# -------------------------
# Routes
# -------------------------

@app.route("/")
def dashboard():
    reports = get_all_reports()

    if not reports:
        return render_template(
            "index.html",
            data=[],
            reports=[],
            selected=None,
            critical=0,
            high=0,
            medium=0
        )

    selected = request.args.get("report", reports[0])
    data = load_report(selected)

    critical = sum(1 for d in data if d["severity"] == "CRITICAL")
    high = sum(1 for d in data if d["severity"] == "HIGH")
    medium = sum(1 for d in data if d["severity"] == "MEDIUM")

    formatted_reports = [(r, format_timestamp(r)) for r in reports]

    return render_template(
        "index.html",
        data=data,
        reports=formatted_reports,
        selected=selected,
        critical=critical,
        high=high,
        medium=medium
    )


# -------------------------
# RUN SCAN (REAL AWS)
# -------------------------

@app.route("/run_scan", methods=["POST"])
def run_scan_api():
    findings = aws_run_scan()  # call real scanner

    reports = get_all_reports()
    latest = reports[0] if reports else None

    return jsonify({
        "status": "success",
        "data": findings,
        "latest_report": latest,
        "all_reports": reports
    })


# -------------------------
# DOWNLOAD REPORT
# -------------------------

@app.route("/download/<filename>")
def download(filename):
    path = os.path.join(REPORTS_FOLDER, filename)
    return send_file(path, as_attachment=True)


# -------------------------
# LAST SCAN TIME
# -------------------------

@app.route("/last_scan")
def last_scan():
    dt = get_latest_report_time()

    if not dt:
        return {"last_scan": None}

    return {"last_scan": dt.isoformat()}

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    return response


# -------------------------
# AI: Explain Finding
# -------------------------
@app.route('/explain_finding', methods=['POST'])
def explain_finding():
    data = request.get_json() or {}

    # minimal fields
    resource = data.get('resource')
    ftype = data.get('type')
    issue = data.get('issue')
    severity = data.get('severity')
    impact = data.get('impact')

    if not GEMINI_API_KEY:
        return jsonify({
            'error': 'GEMINI_API_KEY not configured. Set environment variable GEMINI_API_KEY to enable AI explanations.'
        }), 400

    # Build prompt — explicitly ask for clean JSON without code blocks
    prompt = (
        f"You are a cloud security assistant. Explain the following finding concisely and provide 3 practical remediation steps. "
        f"Return ONLY valid JSON (no code blocks, no markdown, no backticks) with these exact keys: explanation (string), remediation (array of 3 strings).\n\n"
        f"Resource: {resource}\n"
        f"Type: {ftype}\n"
        f"Issue: {issue}\n"
        f"Severity: {severity}\n"
        f"Impact: {impact}"
    )

    # Use v1 endpoint for Gemini models (gemini-2.5-flash, etc.)
    url = f"https://generativelanguage.googleapis.com/v1/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"

    body = {
        'contents': [
            {
                'role': 'user',
                'parts': [{ 'text': prompt }]
            }
        ],
        'generationConfig': {
            'temperature': 0.1,
            'maxOutputTokens': 512
        }
    }

    try:
        resp = requests.post(url, json=body, timeout=15)
        resp.raise_for_status()
        j = resp.json()

        # Gemini API returns candidates with text content
        output = ''
        if 'candidates' in j and len(j['candidates']) > 0:
            candidate = j['candidates'][0]
            if 'content' in candidate and 'parts' in candidate['content']:
                parts = candidate['content']['parts']
                if parts and 'text' in parts[0]:
                    output = parts[0]['text'].strip()
        else:
            output = json.dumps(j)

        # Strip code block markers if Gemini wrapped it
        if output.startswith('```json'):
            output = output.replace('```json', '').replace('```', '').strip()
        elif output.startswith('```'):
            output = output.replace('```', '').strip()

        # Try to parse the model output as JSON. If it is valid JSON and
        # contains the expected keys, return it as structured JSON so the
        # frontend can render it nicely. Otherwise, return the raw text
        # under the `explanation` key.
        try:
            parsed = json.loads(output)
            if isinstance(parsed, dict) and 'explanation' in parsed:
                return jsonify(parsed)
        except Exception:
            parsed = None

        return jsonify({ 'explanation': output })

    except Exception as e:
        return jsonify({ 'error': str(e) }), 500
# -------------------------
# MAIN
# -------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    app.run(host="0.0.0.0", port=port)