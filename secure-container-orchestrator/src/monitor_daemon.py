import definition
import app
import urllib
import time
import os.path
import json
import urllib2
import poster
import copy
from docker import docker



UPPER_THRESHOLD = 3 
LOWER_THRESHOLD = -1



def stats_string_to_dict(stats_lines):
    stats_dict = {}
    for line in stats_lines:
        line = line.strip('\n')
        if len(line) > 2:
            key_value = line.split(": ")
            stats_dict[key_value[0][1:]] = key_value[1]
    return stats_dict


def get_cpu_stats(cluster_id):
    available_nodes = app.get_available_nodes()
    stats_dict = {}
    stats_lines = []
    #GETTING DOCKER CPU STATS FROM ALL INSTANCES IN ALL NODES
    for node in available_nodes:
        if node.get_ip() != "localhost":
            url = 'http://' + node.get_ip() + ":5001/cpu_stats/" + cluster_id
            node_stats_table = urllib2.urlopen(url).read()
            node_stats_lines = node_stats_table.split('\n')
            stats_dict.update(stats_string_to_dict(node_stats_lines)) 
        else:
            node_stats_table = docker.stats_cpu()
            node_stats_lines = node_stats_table.split('\n')
            #TURNING STATS STRING LINES INTO {INSTANCE_ID -> CPU_STAT} DICTIONARY
            all_stats_dict = stats_string_to_dict(node_stats_lines)
            cluster_instances_ids = docker.get_instance_ids_by_id(cluster_id)
            
            #REMOVING STATS FROM INSTANCES THAT ARE NOT FROM THE DESIRED CLUSTER
            for key in all_stats_dict:
                if key in cluster_instances_ids:
                    stats_dict[key] = all_stats_dict[key]
    print "[INFO] current instances for " + cluster_id + " are: " + str(stats_dict)
    stats = stats_dict.values()
    index = 0
    #REMOVING PERCENTAGE CHARACTER FROM CPU STATS VALUES AND TURNING THEM INTO INTS
    for stat in stats:
        stat = stat[:-2]
        stat = float(stat)
        stats[index] = stat
        index += 1
    return stats

def add_instance(image_id, mem, port):
    #SENDING REQUEST AN "ADD NEW CONTAINER INSTANCE TO THE MANAGER
    url = 'http://localhost:5001/add'
    form_data = {'image_id' : image_id, 'network' : image_id, 'mem' : str(mem), 'port' : port}
    params = urllib.urlencode(form_data)
    response = urllib2.urlopen(url, params)
    result = response
    return response

def remove_instance(image_id):
    url = 'http://localhost:5001/remove/' + image_id
    response = urllib2.urlopen(url, data="")
    result = response
    return response

#EVERY 4 SECONDS, VERIFY CURRENTLY CREATED CLUSTERS MEAN CPU USAGE STATS. IF OVER THRESHOLD, ADD NEW INSTANCE TO CLUSTER
stats_mean_record = {}
while True:
    if os.path.isfile((definition.ROOT_PATH + "/data/clusters.json")):
       #Open clusters file. It gets written to in app.py in cluster creation methods
        with open(definition.ROOT_PATH + "/data/clusters.json", 'rw') as clusters_file:
            clusters = json.load(clusters_file)
            clusters_file.seek(0)
            #update instances for each registered cluster
            for cluster in clusters:
                cluster_id = cluster['cluster_id']
                mem = cluster['mem']
                port = cluster['port']
                min_instances = cluster['instances']
                #get cpu stats for all containers in this clusters in all nodes it has been deployed
                stats = get_cpu_stats(cluster_id)
                amount_of_instances = len(stats)
                print "[DEBUG] min_instances is " + str(min_instances) + "/ amount_of_instances is " + str(amount_of_instances) + " for cluster " + cluster_id
                #get the mean cpu consumption of the containers
                stats_mean = sum(stats)/amount_of_instances
                #add the last mean cpu consumption to the history of cpu consumption measurements
                if not cluster_id in stats_mean_record.keys():
                    stats_mean_record[cluster_id] = []
                stats_mean_record[cluster_id].append(stats_mean)
                #remove cpu consumption measure if it is earlier than three iterations old (should be customizable)
                if (len(stats_mean_record[cluster_id]) > 3):
                    stats_mean_record[cluster_id] = stats_mean_record[cluster_id][1:]
                    stats_ratio = sum(stats_mean_record[cluster_id])
                    if stats_ratio > UPPER_THRESHOLD:
                        response = add_instance(cluster_id, mem, port)
                        print response
                    elif stats_ratio < LOWER_THRESHOLD and amount_of_instances > min_instances:
                        response = remove_instance(cluster_id)                    
            time.sleep(4)
            print "I'm alive"
            clusters_file.close()
    else:
        time.sleep(4)
