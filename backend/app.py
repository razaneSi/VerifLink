from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import analyze_url
from messagesScan import analyze_message

app = Flask(__name__)
CORS(app)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_url(url)
    return jsonify(result)

@app.route("/analyze-message", methods=["POST"])
def analyze_message_route():
    data = request.get_json(silent=True) or {}
    sender  = (data.get("sender")  or "").strip()
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"error": "Missing 'message' field"}), 400

    result = analyze_message(sender, message)
    return jsonify(result)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

if __name__ == "__main__":
    app.run(debug=True)