from flask import Flask, request, jsonify
from analyzer import analyze_url

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_url(url)
    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)