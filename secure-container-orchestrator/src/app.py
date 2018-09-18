#flask/bin/python
from flask import Flask
from flask import request
from flask import send_file
from docker import docker
from merge import merger
from merge import haproxy
import poster
from node import Node
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
import subprocess
import urllib
import urllib2
from merge.ip_strings import IPStrings
import json
import os
import definition
import unicodedata
import shutil
import socket
from threading import Thread



socket.gethostbyname(socket.gethostname())

main_lb_image_label = "lb_main"
main_lb_dockerfile_path = definition.ROOT_PATH + '/../../assets/support-containers/load_balancer/main_load_balancer'
haproxy_dockerfile_dir = definition.ROOT_PATH + '/../../assets/support-containers/load_balancer/'
service_dispatcher_dockerfile_dir = definition.ROOT_PATH + '/../../assets/support-containers/service_dispatcher/'
node_data_path = definition.ROOT_PATH + '/../../assets/nodes_data.json'
clusters_file_path = definition.ROOT_PATH + '/data/clusters.json'
service_dispatcher_id = "service_dispatcher"
cluster_data_dir = definition.ROOT_PATH + '/../../data/'
haproxy_prefix = "haproxy_"
ip_strings = IPStrings()
dockerfile_dir = ""
dockerfile_path = ""
bound_port = "8888"
lb_port = "81"
cluster_port = 82
server_pointer = 0
current_port = 81
INSTANCE_LIMIT = 10


#available_nodes_ips = ["localhost", "10.30.0.20"]
#available_nodes_ips = ["10.5.0.27", "10.5.0.9"]
#available_nodes = [Node('localhost'), Node('10.30.0.20')]
#available_nodes = [Node('10.5.0.20'), Node('10.5.0.9')]
available_nodes_ips = []
available_nodes = []



def load_nodes():
    with open(node_data_path, "r") as node_data_file:
        global available_nodes_ips
        global available_nodes
        node_data = json.load(node_data_file)
        available_nodes_ips = node_data
        available_nodes = [Node(node_ip) for node_ip in available_nodes_ips]
    return available_nodes


class BuildAgent(Thread):
    def __init__(self, form_data, url):
        Thread.__init__(self)
        self.form_data = form_data
        self.url = url

    def run(self):
        datagen, headers = multipart_encode(self.form_data)
        request = urllib2.Request(self.url, datagen, headers)
        response = urllib2.urlopen(request)
        print response.read()


app = Flask(__name__)

clusters = []

@app.route('/')
def index():
    return "Hello, World!"

#CREATE: takes a cluster id, an application package, a dockerfile, a number of instances and a memory limit per instance.
#Builds an image based from the dockerfile and package. Creates the instance amount with the give memory limit and adds a 
#load balancer to the resulting cluster. Publishes the load balancer ip to the user.
# TODO: Separate this method into smaller parts (template)


def _set_dockerfile_path(id):
    global dockerfile_dir
    global dockerfile_path
    dockerfile_dir = definition.ROOT_PATH + '/dockerfiles/' + id
    dockerfile_path = dockerfile_dir + '/Dockerfile'

def _deploy_files(id, package, dockerfile_data):
    if not os.path.exists(dockerfile_dir):
        os.makedirs(dockerfile_dir)
    print("[DEBUG] dockerfile_dir is " + dockerfile_dir)
    merger.deploy_package(dockerfile_dir, package)
    print("[LOG] package deployed")
    merger.write_data(dockerfile_path, dockerfile_data)
    section = merger.get_section()
    merger.insert_section(dockerfile_path)

@app.route('/create_cluster', methods=['POST'])
def create_cluster():
    cluster = {
        # TODO: Existing ids should not be allowed
        'id': request.form['id'],
        'dockerfile': request.form['dockerfile'],
        'instances': request.form['instances'],
        'package' : request.files['package'],
        'mem' : request.form['mem'],
        'port' : request.form['port']
    }
    volume = {
         'volume_size': request.form['volume_size']
    }
    id = cluster['id'].strip("'")
    if not _validate_cluster_id(id):
        return '[ERROR] The chosen id is already taken. Please, chose another one. Operation aborted'
    package = cluster['package']
    dockerfile_data = cluster['dockerfile']
    dockerfile_data.encode('ascii','ignore')
    dockerfile_data = dockerfile_data.replace(r'\n', '\n')
    mem = cluster['mem']
    port = cluster['port']
    instances = int(cluster['instances'])
    if instances > INSTANCE_LIMIT:
        return '[ERROR] The instances amount value exceeds the limit per cluster. Try a lower value'
    volume_size = volume['volume_size']
    _set_dockerfile_path(id)
    print("[DEBUG] Dockerfile path is " + dockerfile_path)
    register_openers()
    _deploy_files(id, package, dockerfile_data)
    print("[LOG] section inserted")
    container_locations = _create_cluster_components(id, volume_size, dockerfile_data, package, instances, mem, port)
    if container_locations == None:
        return "[ERROR] Build was unsuccesful. Invalid Dockerfile"
    _record_cluster_data(id, instances, mem, port, container_locations)
    success = True
    cluster['package'] = package.filename
    merger.write_cluster_data(id, json.dumps(cluster))
    response_bundle_path = merger.create_response_bundle(dockerfile_dir)
    return send_file(response_bundle_path)


def _create_cluster_components(id, volume_size, dockerfile, package, instances, mem, port):
    global cluster_port
    global server_pointer
    register_openers()

    for node in available_nodes:
        if node.get_ip() != "localhost":
            url = 'http://' + node.get_ip() + ":5001/build"
            package_filename = merger.get_short_filename_from_package(package)
            form_data = {'image_id' : id, 'dockerfile' : dockerfile, 'data': open(dockerfile_dir + '/' + package_filename)}
            datagen, headers = multipart_encode(form_data)
#            request = urllib2.Request(url, datagen, headers)
            build_agent = BuildAgent(form_data, url)
            build_agent.start()
            
#            response = urllib2.urlopen(request)
#            result = response.read()
    build_agent.join()
    print "[DEBUG] join completed"
    add_cluster_frontend_to_main_load_balancer(cluster_port, id)
    cluster_port += 1
    print "[DEBUG] dockerfile dir is  " +  dockerfile_dir
    if "localhost" in [node.get_ip() for node in available_nodes]:
        if not docker.build('-t', id, dockerfile_dir):
            print("[ERROR] build unsuccessfull")
            return None
    print("[LOG] image built")
    success = True
    volume_created = _create_volume(id, volume_size)
    if not volume_created:
        print("[ERROR] volume not created")
        return
    print(volume_created)
    network_created = docker.create_network('--subnet=' + ip_strings.get_current_network() + "/16", id)
    if not network_created:
        print("[ERROR] network not created")
        return
    count = 0
    container_locations = {}
    #TODO: Move instantiation to a different module
    for i in range(instances):
        container_location = _create_instance(id, mem, port, available_nodes_ips[count])
        container_locations.update(container_location)
        if count == len(available_nodes) - 1:
            count = 0
        else:
            count += 1
    if not success:
        print("[ERROR] instances not created")
        return None
    else:
        print("[LOG] instances created")
	return container_locations

@app.route('/add', methods=['POST'])
def add_instance():
    image_id = request.form["image_id"]
    mem = request.form["mem"]
    port = request.form['port']
    global cluster_port
    global server_pointer
    container_location = _create_instance(image_id, mem, port, available_nodes[server_pointer].get_ip())
    _add_container_to_record(image_id, container_location)
    server_pointer += 1
    server_pointer = server_pointer % len(available_nodes)
    return "Instance added succesfully to cluster " + image_id

def _create_instance(image_id, mem, port, ip, update_lb=False):
    global current_port
    if ip != "localhost":
        url = 'http://' + ip + ':5001' + '/run'
        form_data = {'image_id' : image_id, 'network' : image_id, 'mem' : str(mem), 'port' : port}
        params = urllib.urlencode(form_data)
        response = urllib2.urlopen(url, params)
        result = json.load(response)
        main_lb_ip = docker.get_ip_by_name(main_lb_image_label)
        created = True
        lb_port = result['lb_port']
        container_id = result['container_id']
        update_main_load_balancer(image_id, ip, str(lb_port))
    else:
        container_id = docker.run('--network', image_id, '-m', str(mem) + 'M', '--device=/dev/isgx','-d', '--cpus=0.5', '-v', image_id + ':' + docker.default_volume_path, image_id)
        #if there are instances with this image, remove the current load balancer, reverse one port number in the load balancer port counter and the recreate the load balancer.
        instances = docker.get_instance_names_by_id(haproxy_prefix + image_id)
        if instances:
            load_balancer_instance = docker.get_instance_names_by_id(haproxy_prefix + image_id)[0]
            load_balancer_ip = docker.get_ip_by_name(load_balancer_instance)
            _remove_current_load_balancer(load_balancer_instance, image_id) 
            current_port -= 1
            lb_port = _add_load_balancer(image_id, port, ip=load_balancer_ip)
        else:
            lb_port = _add_load_balancer(image_id, port)
        update_main_load_balancer(image_id, "127.0.0.1", str(lb_port))
   
    return {container_id: ip}

@app.route('/create_single_client_cluster', methods=['POST'])
def create_single_client_cluster():
    cluster = {
    # TODO: Existing ids should not be allowed
       'id': request.form['id'],
       'dockerfile': request.form['dockerfile'],
       'package' : request.files['package'],
       'mem' : request.form['mem']
    }
    volume = {
       'volume_size': request.form['volume_size']
    }
    id = cluster['id']
    package = cluster['package']
    dockerfile_data = cluster['dockerfile']
    dockerfile_data.encode('ascii','ignore')
    dockerfile_data = dockerfile_data.replace(r'\n', '\n')
    mem = cluster['mem']
    volume_size = volume['volume_size']
    dockerfile_dir = (definition.ROOT_PATH + '/dockerfiles/' + id).encode("ascii")
    dockerfile_path = dockerfile_dir + '/Dockerfile'
    if not os.path.exists(dockerfile_dir):
        os.makedirs(dockerfile_dir)
    merger.deploy_package(dockerfile_dir, package)
    merger.write_data(dockerfile_path, dockerfile_data)
    section = merger.get_section()
    merger.insert_section(dockerfile_path, section)
    dispatcher_ip =  _create_service_dispatcher(id, cluster, volume)
    quote = get_mock_up_quote(id)
    response_bundle_path = merger.create_response_bundle(dockerfile_dir, package, quote)
    return send_file(response_bundle_path)


    
@app.route('/create_instance_single_client_cluster/<string:id>/<string:client_id>', methods=['POST'])
def create_instance_single_client_cluster(id, client_id):
    meta_string = ""
    with open(service_dispatcher_dockerfile_dir + id + "/meta.json") as file:
        meta_string = file.read()
    params = json.loads(meta_string)
    mem = params['mem']
    volume_size = params['volume_size']
    volume_name = id + client_id
    dockerfile_dir = definition.ROOT_PATH + '/dockerfiles/' + id
    docker.build("-t", id, dockerfile_dir)
    volume_created = _create_volume(volume_name, volume_size)
    name = (docker.run_get_name('-m', str(mem) + 'M', '-d', '-v', volume_name + ':' + docker.default_volume_path, id)).rstrip()
    container_ip = docker.get_ip_by_name(name)
    return container_ip, 201
    
    ## TODO: build and run with the parameters written

def _create_service_dispatcher(id, cluster, volume):
    service_dispatcher_dir = service_dispatcher_dockerfile_dir + id
    if not os.path.exists(service_dispatcher_dir):
        os.makedirs(service_dispatcher_dir)
    section = merger.get_section()
    dockerfile_dir = (definition.ROOT_PATH + '/dockerfiles/' + id).encode("ascii")
    dockerfile_path = dockerfile_dir + '/Dockerfile'
    merger.insert_section(dockerfile_path, section)
    print("[LOG] section inserted")
    instance_metadata_path = service_dispatcher_dir + "/meta.json"
    cluster['volume_size'] = volume['volume_size']
    del cluster['package']
    merger.write_data(instance_metadata_path, json.dumps(cluster))
    shutil.copy(service_dispatcher_dockerfile_dir + "Dockerfile", service_dispatcher_dir)
    manager_address = socket.gethostbyname(socket.gethostname())
    docker.build('-t', service_dispatcher_id, service_dispatcher_dockerfile_dir)
    docker.run('-e', "ID=" + id, '-e', 'MANAGER=' + manager_address, '-d',  service_dispatcher_id)
    return docker.get_ip_list_by_id(service_dispatcher_id)


#LIST_INSTANCES: shows the available instances
@app.route('/list/<string:image_id>', methods=['GET'])
def list_instances(image_id):
    with open(clusters_file_path, 'r') as clusters_file:
        if os.stat(clusters_file_path).st_size == 0:
            return []
        cluster_list = json.load(clusters_file)
        locations = [cluster['container_location'] for cluster in clusters]
    instances_list = docker.ps()
    return instances_list

#LIST_IMAGES: shows the available images
@app.route('/image_list', methods=['GET'])
def list_images():
    with open(clusters_file_path, 'r') as clusters_file:
        if os.stat(clusters_file_path).st_size == 0:
            return []
        cluster_list = json.load(clusters_file)
        cluster_ids = [cluster['id'] for cluster in cluster_list]
        return cluster_ids    

@app.route('/remove/<string:image_id>', methods=['DELETE'])
def remove_instance_from_cluster(image_id):
    global server_pointer
    ip = available_nodes[server_pointer].get_ip()
    #if the choosen node is not local, send a request to the chosen node to remove an instance with the image_id
    if ip != "localhost":
        url = 'http://' + ip + ':5001' + '/remove'
        form_data = {'image_id' : image_id}
        params = urllib.urlencode(form_data)
        response = urllib2.urlopen(url, params)
        result = json.load(response)
        #update the main load balancer to remove the container from the chosen instance
        main_lb_ip = docker.get_ip_by_name(main_lb_image_label)
        removed = True
        lb_port = result['lb_port']
        container_id = result['container_id']        
        update_main_load_balancer(image_id, ip, str(lb_port))
    else:
        #if the chosen node is the local node, remove an instance with with the image_id straight from docker
        removables = docker.get_instance_ids_by_id(image_id)
        removed = docker.rm('-f', removables[-1])
        #update main load balancer to remove the container from the chosen instance
        lb_port = _add_load_balancer(image_id, port)
        update_main_load_balancer(image_id, "127.0.0.1", str(lb_port))
    #update the server pointer to the previous server. If it goes down to zero, set it to the last one on the list.
    _remove_container_from_record(image_id, container_id)
    server_pointer -= 1
    if server_pointer == 0:
        server_pointer = len(available_nodes) - 1


#REMOVE_INSTANCE: removes the instance that has the given instance id
@app.route('/remove_instance/<string:container_id>', methods=['DELETE'])
def remove_instance(container_id):
    docker.stop(container_id)
    success = docker.rm(container_id)
    return str(success) + '\n', 200

#REMOVE_IMAGE: remove an image by ID. Forces removal of all containers with that image
@app.route('/remove_image/<string:image_id>', methods=['DELETE'])
def remove_image(image_id):
    global server_pointer
    ip = available_nodes[server_pointer].get_ip()
    #if the choosen node is not local, send a request to the chosen node to remove an instance with the image_id
    if ip != "localhost":
        url = 'http://' + ip + ':5001' + '/remove_image'
        form_data = {'image_id' : image_id}
        params = urllib.urlencode(form_data)
        response = urllib2.urlopen(url, params)
        result = json.load(response)
    else:
        #if the chosen node is the local node, remove an instance with with the image_id straight from docker
        removables = docker.get_instance_ids_by_id(image_id)
        for index, removable in enumerate(removables):
            removed = [docker.rm('-f', removables[index])]
        #update main load balancer to remove the container from the chosen instance
        lb_port = _add_load_balancer(image_id, None)
        update_main_load_balancer(image_id, "127.0.0.1", str(lb_port))
    #update the server pointer to the previous server. If it goes down to zero, set it to the last one on the list.
    for removable in removables:
        _remove_container_from_record(image_id, removable)
    server_pointer -= 1
    if server_pointer == 0:
        server_pointer = len(available_nodes) - 1

    success_containers = docker.rmi(image_id)
    success_load_balancer = docker.rmi(haproxy_prefix + image_id)
    success_volume = docker.remove_volume(image_id)
    success_network = docker.remove_network(image_id)
    merger.remove_app_data(image_id)
    success = success_containers and success_load_balancer and success_volume and success_network    
    return str(success) + '\n', 200

@app.route('/cpu_stats/<string:image_id>', methods=['GET'])
def get_cpu_stats(image_id):
#    image_id = request.form['image_id']
    ancestor_image_instances_ids = docker.get_instance_ids_by_id(image_id)
    cluster_instances_ids = []
    for instance in ancestor_image_instances_ids:
        if docker.get_image(instance).strip('\n').strip('"') == image_id:
            cluster_instances_ids.append(instance)
    stats = docker.stats_cpu()
    stats_list = stats.split('\n')
    match_lines = []
    for cluster_instance in cluster_instances_ids:
        for stats_line in stats_list:
            if cluster_instance in stats_line:
                match_lines.append(stats_line)
    match_stats = '\n'.join(match_lines)
    print "[DEBUG] image_id stats are " + match_stats
    print "[DEBUG] current_port is " + str(current_port)
    return match_stats

    

#PRIVATE; ADD_LOAD_BALANCER: used by CREATE to add a load balancer to a given cluster by id
def _add_load_balancer(image_id, port, ip=None):
    global current_port
    lb_image_label = haproxy_prefix + image_id
    lb_dockerfile_path = haproxy_dockerfile_dir + image_id
    ip_list = docker.get_ip_list_by_id(image_id)
    if not ip_list:
        return None
    haproxy.add_nodes(image_id, port, ip_list)
    docker.build('-t', lb_image_label, lb_dockerfile_path)
    if not ip:
<<<<<<< HEAD
        created = docker.run('--network=' + image_id, '-d', '--cpus=0.5', '-p', str(current_port) + ":" + str(current_port), lb_image_label)
    else:
        networkID = docker.get_network_name_by_id(image_id)
        created = docker.run('--network=' + image_id, '--ip', ip, '-d',  '--cpus=0.5', '-p', str(current_port) + ":" + str(current_port), lb_image_label)
=======
         created = docker.run('--network=' + id, '-d', '-p', '80:80', lb_image_label)
    else:
         networkID = docker.get_network_name_by_id(id)
         created = docker.run('--network=' + id, '--ip', ip, '-d', '-p', '80:80', lb_image_label)
>>>>>>> a93139078caac6f5316b15c2b42f663c2736e747
    if created:
        current_port += 1
        print('[INFO] Load balancer created succesfully')
        return current_port - 1  

def _add_to_main_load_balancer(image_id, lb_ip, container_ips, port):
    current_ip = docker.get_ip_list_by_id(main_lb_image_label)
    haproxy.add_lb_to_main_lb(lb_ip, container_ips, port)
    docker.build('-t', main_lb_image_label, main_lb_dockerfile_path)
    main_load_balancer_instance = docker.get_instance_names_by_id(main_lb_image_label)[0]
    docker.stop(main_load_balancer_instance)
    eocker.rm(main_load_balancer_instance)
    created = docker.run('--network=' + main_lb_image_label, '--ip', currrent_ip, '-d', main_lb_image_label)        
    return True


#PRIVATE; CREATE_VOLUME: prepares docker.create_volume arguments and calls it
def _create_volume(volume_name, volume_size):
    volume_size_string = "o=size=" + str(volume_size) + "g"
    return docker.create_volume(volume_size_string, volume_name) 


def _get_note_by_ip(ip):
    node_index = 0
    for node in available_nodes:
        if node.get_lbs[node_index][1] == ip:
            return available_nodes[node_index]
        node_index += 1
    return None

def update_main_load_balancer(image_id, node_ip, lb_port):
    main_lb_ip = docker.get_ip_by_name(main_lb_image_label)
    url = 'http://' + main_lb_ip + ':5000/update'
    print "[DEBUG] url is: " + url
    lb_update_data = ({'image_id' : image_id, 'node_ip' : node_ip, 'lb_port': str(lb_port)})
    lb_update_data = json.dumps(lb_update_data)
    req = urllib2.Request(url, lb_update_data, {'Content-Type': 'application/json'})
    response = urllib2.urlopen(req)
    str_response = response.read()
    print "[LOG] update is " + str_response
    response.close()


def add_cluster_frontend_to_main_load_balancer(cluster_port, image_id):
    main_lb_ip = docker.get_ip_by_name(main_lb_image_label)
    url = 'http://' + main_lb_ip + ':5000/create'
    lb_update_data = ({'cluster_port' : cluster_port, 'image_id' : image_id})
    lb_update_data = json.dumps(lb_update_data)
    print "[DEBUG] main load balancer url is: " + url
    req = urllib2.Request(url, lb_update_data, {'Content-Type': 'application/json'})
    response = urllib2.urlopen(req)
    str_response = response.read()
    print str_response


def get_available_nodes():
    available_nodes = load_nodes()
    return available_nodes

def _record_cluster_data(cluster_id, instances, mem, port, container_locations):
    is_empty = False
    with open(clusters_file_path, 'a') as clusters_file:
        if os.stat(clusters_file_path).st_size == 0:
            cluster_list = []
            print "[DEBUG] New cluster list created"
        else:
            cluster_list = json.load(clusters_file)
            print "[DEBUG] append to cluster list"
        new_cluster = {'cluster_id': cluster_id, 'instances': instances, 'mem': mem, 'port': port, 'container_locations': container_locations}
        cluster_list.append(new_cluster)
        print "[DEBUG] Cluster list is " + str(cluster_list)
        json.dump(cluster_list, clusters_file)
        clusters_file.seek(0)
        clusters_file.close()

def _remove_current_load_balancer(load_balancer_instance, image_id):
    docker.stop(load_balancer_instance)
    docker.rm(load_balancer_instance)
    docker.rmi(haproxy_prefix + image_id)


def update_load_balancer(container_params):
    image_id = container_params['image_id']
    load_balancer_instance = docker.get_instance_names_by_id(haproxy_prefix + image_id)[0]
    load_balancer_ip = docker.get_ip_by_name(load_balancer_instance)
    _remove_current_load_balancer(load_balancer_instance, image_id)
    load_balancer_unavailable = True
    lb_port = _add_load_balancer(container_params, ip=load_balancer_ip)
    while load_balancer_unavailable:
        load_balancer_list = docker.get_instance_names_by_id(haproxy_prefix + image_id)
        if load_balancer_list:
            load_balancer_instance = load_balancer_list[0]
            load_balancer_unavailable = False
        else:
            lb_port = _add_load_balancer(container_params)
        container_ips = docker.get_ip_list_by_id(container_params['image_id'])
        return lb_port

def _validate_cluster_id(cluster_id):
    if not os.path.isfile(clusters_file_path):
        return True
    with open(clusters_file_path, 'r') as clusters_file:
        if os.stat(clusters_file_path).st_size == 0:
            return True
        else:
            cluster_list = json.load(clusters_file)
            clusters_file.seek(0)
        for cluster in cluster_list:
            if cluster['cluster_id'] == cluster_id:
                return False
        return True   


def _add_container_to_record(cluster_id, container_location):
    with open(clusters_file_path, 'w+') as clusters_file:
        cluster_list = json.load(clusters_file)
        index = 0
        for cluster in cluster_list:
            if cluster['cluster_id'] == cluster_id:  
                cluster_list[index]['container_locations'].update(container_location) 
            index += 1
        clusters_file.seek(0)
        json.dump(cluster_list, clusters_file) 
        print "[DEBUG] data writen to cluster_file was " + str(cluster_list)
        clusters_file.seek(0)
        clusters_file.close()
    

def _remove_container_from_record(cluster_id, container_id):
    with open(clusters_file_path, 'r+') as clusters_file:
        cluster_list = json.load(clusters_file)
        index = 0
        for cluster in cluster_list:
            if cluster['cluster_id'] == cluster_id:
                for full_id in cluster_list[index]['container_locations'].keys():
                    print (full_id, container_id)
                    if full_id[:11] == container_id:
                        print "[DEBUG] Removing container. Container id is %s" % container_id
                        del cluster_list[index]['container_locations'][full_id]
            index += 1
        clusters_file.seek(0)
        json.dump(cluster_list, clusters_file)
        clusters_file.close()

if __name__ == '__main__':
    load_nodes()
    app.run(host='0.0.0.0', port=5001)
