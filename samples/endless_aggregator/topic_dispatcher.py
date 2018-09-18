#flask/bin/python
from flask import Flask
from flask import request
import socket

app = Flask(__name__)

@app.route('/get_ip', methods=['GET'])
def get_ip():
    return socker.gethostbyname(socket.gethostname())
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1620)
