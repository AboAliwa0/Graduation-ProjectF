from flask import Flask, request, jsonify, render_template
from main import run

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    url = data.get("url")

    try:
        results = run(url)  # 👈 استدعاء مباشر

        return jsonify({"results": "\n".join(results)})

    except Exception as e:
        return jsonify({"error": str(e)})


if __name__ == "__main__":
    app.run(debug=True)