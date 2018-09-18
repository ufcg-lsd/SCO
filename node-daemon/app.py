from flask import Flask
from docker import docker
from merge import haproxy
from flask import jsonify
from merge.ip_strings import IPStrings
import util
import os 
from flask import request


dir_path = os.path.dirname(os.path.realpath(__file__))
haproxy_prefix = "haproxy_"
haproxy_dockerfile_dir = dir_path + '/assets/support-containers/load_balancer/'
ip_strings = IPStrings()

app = Flask(__name__)


### TODO: MAKE THIS PERSISTENT
images_with_load_balancers = []
images_with_containers = []
current_port = 80


@app.route('/')
def test():
    return "Hello, World!"

@app.route('/build', methods=['POST'])
def build():
    image_resources = {
        'image_id': request.form['image_id'],
        'dockerfile' : request.form['dockerfile'],
        'data' : request.files['data']
    }
    resource_directory = _deploy_files(image_resources['image_id'], image_resources['dockerfile'], image_resources['data'])
    print "[DEBUG] resource_directory is: " + resource_directory
    print "[DEBUG] image id is: " + image_resources['image_id']
    result = docker.build('-t', image_resources['image_id'], resource_directory)
    print "[DEBUG] result is: " + str(result)
    if result:
        return "[INFO] Image " + image_resources['image_id'] + " built successfully."
        image_ids.append(image_resources['image_id'])
    else:
        return "[ERROR] Image " + image_resources['image_id'] + " could not be built. Check your parameters"

@app.route('/run', methods=['POST'])
def run():
    container_params = {
        'image_id': request.form['image_id'],
        'network': request.form['network'],
        'mem': request.form['mem'],
        'port': request.form['port']
    }
    #CREATES A LOAD BALANCER IF IMAGE DOESN'T HAVE ONE
    image_has_containers = False
    docker.create_network('--subnet=' + ip_strings.get_current_network() + "/16", container_params['network'])
    if not container_params['image_id'] in images_with_load_balancers:
        _add_load_balancer(container_params)
    container_id = docker.run_get_name('--network', container_params['network'], '-m', container_params['mem'] + 'M', '--device=/dev/isgx','-d', container_params['image_id'])
    if container_id:
        lb_port = update_load_balancer(container_params)
        return jsonify({'lb_port':  lb_port, 'container_id': container_id})
    else:
        return "[ERROR] Container Could not be created. Check your parameters"

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

@app.route('/remove', methods=['DELETE'])
def remove():
    image_id = request.form['image_id']
    removables = docker.get_instances_ids_by_id(image_id)
    container_id = docker.rm('-f', removables[-1])
    if container_id:
        lb_port = update_load_balancer(image_id)
        return jsonify({'lb_port': lb_port, 'container_id': container_id})
    else:
        return "[ERROR] Container Could not be removed. Check your parameters"

def update_load_balancer(container_params):
    global images_with_load_balancers
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
            images_with_load_balancers.append(container_params['image_id'])
        container_ips = docker.get_ip_list_by_id(container_params['image_id'])
        return lb_port

def _add_load_balancer(container_params, ip=None):
    global current_port
    lb_image_label = haproxy_prefix + container_params['image_id']
    lb_dockerfile_path = haproxy_dockerfile_dir + container_params['image_id']
    ip_list = docker.get_ip_list_by_id(container_params['image_id'])
    if len(ip_list) == 0 and ip:
        return None
    haproxy.add_nodes(container_params['image_id'], container_params['port'], ip_list)
    ### DEBUG ###
    docker.build('-t', lb_image_label, lb_dockerfile_path)
    if not ip:
        current_port += 1
        created = docker.run('--network=' + container_params['image_id'], '-d', '-p', str(current_port) + ':' + str(current_port), lb_image_label)
    else:
        networkID = docker.get_network_name_by_id(container_params['image_id'])
        created = docker.run('--network=' + container_params['image_id'], '--ip', str(ip), '-d', '-p', str(current_port) + ':' + str(current_port) , lb_image_label)
    if created:
        print('[INFO] Load balancer created succesfully')
        if not ip:
            print '[DEBUG] Adding load balancer. The port used was ' + str(current_port) 
            return current_port - 1
        else:
            print '[DEBUG] Updating load balancer. The port used was ' + str(current_port) 
            return current_port

def _remove_current_load_balancer(load_balancer_instance, image_id):
    docker.stop(load_balancer_instance)
    docker.rm(load_balancer_instance)
    docker.rmi(haproxy_prefix + image_id)

def _deploy_files(image_id, dockerfile, app_data):
    dockerfile_dir = dir_path + '/data/' + image_id
    print dockerfile_dir
    if not os.path.exists(dockerfile_dir):
        os.makedirs(dockerfile_dir)
    util.deploy_package(dockerfile_dir, app_data)
    dockerfile = dockerfile.replace(r'\n', '\n')
    util.write_data(dockerfile_dir + '/Dockerfile', dockerfile)
    return dockerfile_dir


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)

