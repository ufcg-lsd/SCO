from flask import Flask
from flask import request
app = Flask(__name__)

@app.route('/', methods=['POST'])
def validate_credit_card():
    number = request.json['number']


    nlist = []
    nlist = list(number)
    check = int(nlist.pop())
    nlist.reverse()
    for i in range(len(nlist)):
        nlist[i] = int(nlist[i])
        if i % 2 == 0:
            nlist[i] = nlist[i] * 2
    for i in range(len(nlist)):
        if nlist[i] >= 10:
            nlist[i] = nlist[i] - 9
    nsum = sum(nlist)
    if nsum % 10 == check:
        return "Validated!\n", 200
    else:
        return "Invalid Number!\n", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0')
