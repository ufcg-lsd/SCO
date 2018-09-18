#flask/bin/python
from flask import Flask
from flask import request

app = Flask(__name__)
topic_num = 0
subs_topic_num = 0

@app.route('/get_topic', methods=['GET'])
def get_topic():
    global topic_num
    topic = "Topic" + str(topic_num)
    topic_num += 1
    print "[INFO] Incoming Topic Request from " + request.remote_addr
    print "[INFO] Dispatched Topic was " + topic
    return topic

@app.route('/get_subscribed_topic', methods=['GET'])
def get_subscribed_topic():
    global subs_topic_num
    topic = "Topic" + str(subs_topic_num)
    if subs_topic_num >= topic_num:
        print "[INFO] No new Topics available"
        return None
    print "[INFO] Incoming Subscribed Topic Request from " + request.remote_addr
    print "[INFO] Dispatched Subscribed Topic was " + topic
    return topic

   
    
    
    
        
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1620)


