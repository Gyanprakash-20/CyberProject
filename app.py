import os
import tempfile
from flask import Flask, request, jsonify, render_template, send_from_directory
from analyzer import analyze

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB max upload


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith('.pcap'):
        return jsonify({'error': 'Only .pcap files are supported'}), 400

    # Save to a temp file
    tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    try:
        file.save(tmp.name)
        tmp.close()
        results = analyze(tmp.name)
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
