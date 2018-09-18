#!/flask/bin/python
from flask import Flask
from flask import request
import requests
import os

app = Flask(__name__)

@app.route("/<string:user_id>", methods=["POST"])
def create_container(user_id):
    id = os.environ['ID']
    manager_address = os.environ['MANAGER']
    url = "http://" + manager_address + ":5000/create_instance_single_client_cluster/" + id + "/" + user_id
    response = requests.post(url)
    return str(response), 201


if __name__ == '__main__':
    app.run(host='0.0.0.0')

    


