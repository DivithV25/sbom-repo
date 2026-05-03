"""
Python Flask Application for PRISM Scanner Demo
"""
from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        'message': 'PRISM Scanner - Python App',
        'version': '1.0.0'
    })

@app.route('/api/data', methods=['GET'])
def get_data():
    try:
        response = requests.get('https://api.example.com/data')
        return jsonify(response.json())
    except requests.RequestException as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False, port=5000)
