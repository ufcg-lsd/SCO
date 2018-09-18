import argparse
import subprocess
import sys

ps_values = {'CONTAINER_ID': 0, 'IMAGE': 1, 'COMMAND': 2, 'CREATED': 3, 'STATUS': 4, 'PORTS': 5, 'NAMES': 6}
inspect_get_ip_query = '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
default_volume_path = '/src/volume'
networkID_string_start_position = 14
networkID_string_end_position = -2
IPAddress_string_start_position = 14
IPAddress_string_end_position = -2


#PRIVATE; EXECUTE: runs the bash command built by the api functions with the giver arguments
def _execute(args, opts, stdout = False):
    for o in opts:
        args.append(o)
    result = None
    if stdout:
        result = subprocess.check_output(args)
    else:
        result = not subprocess.call(args)
    return result

#PRIVATE; EXECUTE_ORDERED: same as execute, but the opts arguments can be inserted in the desired order
def _execute_ordered(args, opts, opts_order, stdout = False):
     position = 0
     for o in opts:
         args.insert(opts_order[position], o)
         position += 1
     result = None
     if stdout:
         result = subprocess.check_output(args)
     else:
         result = not subprocess.call(args)
     return result

#BUILD: builds an image with the given parameters (quiet mode by default)
def build(*opts):
    args = ['docker', 'build', '-q']
    opts = list(opts)
    return _execute(args, opts)

#REMOVE_IMAGE: removes an image with the given parameters. Forcefully removes containers running with that image
def rmi(*opts):
    args = ['docker', 'rmi', '-f']
    opts = list(opts)
    return _execute(args, opts)

#RUN: creates an instance with the given parameters and returns its id (removes last \n character)
def run(*opts):
    args = ['docker', 'run']    
    opts = list(opts)
    return _execute(args, opts, stdout = True)[:-1]


def run_get_name(*opts):
    args = ['docker', 'run']
    opts = list(opts)
    return _execute(args, opts, stdout = True)

#REMOVE_INSTANCE: removes an instances with the given parameters
def rm(*opts):
    args = ['docker', 'rm']
    opts = list(opts)
    return _execute(args, opts, stdout = True)

#STOP_INSTANCE: stops an instance with the given parameters
def stop(*opts):
    args = ['docker', 'stop']
    opts = list(opts)
    return _execute(args, opts)

#PS: lists all instances, running and exited
def ps(*opts):
    args = ['docker', 'ps', '-a']
    opts = list(opts)
    return _execute(args, opts, stdout = True)

#IMAGES: Lists all images
def images(*opts):
    args = ['docker', 'images']
    opts = list(opts)
    return _execute(args, opts, stdout = True)

#INSPECT: returns metadata from a container with the giver paramenters
def inspect(*opts):
    args = ['docker', 'inspect']
    opts = list(opts)
    return _execute(args, opts, stdout = True)

#CREATE_VOLUME: creates a volume with the given parameters
def create_volume(*opts):
    args = ['docker', 'volume', 'create', '-d', 'local', '--opt', 'type=tmpfs', '--opt', 'device=tmpfs', '--opt', '--name']
    opts = list(opts)
    positions = [10, 12]
    return _execute_ordered(args, opts, positions, stdout = True)

#REMOVE_VOLUME: removes a volume with the given parameters
def remove_volume(*opts):
    args = ['docker', 'volume', 'rm']
    opts = list(opts)
    return _execute(args, opts)

#CP: copies files from instances to containers and vice versa
def cp(*opts):
    args = ['docker', 'cp']
    opts = list(opts)
    return _execute(args, opts)

#CREATE_NETWORK: creates a network with the given parameters
def create_network(*opts):
    args = ['docker', 'network', 'create', '--driver', 'bridge']
    opts = list(opts) 
    return _execute(args, opts)

#REMOVE_NETWORK: removes a network with the given parameter
def remove_network(*opts):
    args = ['docker', 'network', 'rm']
    opts = list(opts)
    return _execute(args, opts)

def stats_cpu(*opts):
    args = ['docker', 'stats', '--no-stream', '--format', '"{{.Container}}: {{.CPUPerc}}"']
    opts = list(opts)
    return _execute(args, opts, True) 

def get_image(instance_id):
    return inspect("--format", '"{{.Config.Image}}"', instance_id)


#GET_INSTANCE_NAMES_BY_ID: return the name of the containers running an image by image id
def get_instance_names_by_id(id):
    names = []
    instances = ps('--filter', 'ancestor=' + id, '--filter', 'status=running')
    instances_lines = instances.split('\n')
    instances_lines.pop(0)
    instances_lines.pop(-1)
    for line in instances_lines:
        line = line.split()
        names.append(line[-1])
    return names

#GET_INSTANCE_IDS_BY_ID: return the docker id from containers running an image by image id
def get_instance_ids_by_id(id):
    names = []
    instances = ps('--filter', 'ancestor=' + id, '--filter', 'status=running')
    instances_lines = instances.split('\n')
    instances_lines.pop(0)
    instances_lines.pop(-1)
    for line in instances_lines:
        line = line.split()
        names.append(line[0])
    return names

 

#GET_IP_LIST_BY_ID: retuns the ips from containers running an image by image id
def get_ip_list_by_id(id):
    names = get_instance_names_by_id(id)
    address = ""
    ips = []
    for name in names:
        found = False
        raw_inspect = inspect(name)
        inspect_lines = raw_inspect.split('\n')
        for line in inspect_lines:
            line = line.strip()
            if line.startswith('"' + 'IPAddress') and not found:
                address = line[IPAddress_string_start_position:]
                address = address[:IPAddress_string_end_position]
                if address == r"":
                    found = False
                else:
                    ips.append(address)
                    found = True
    return ips

def get_network_name_by_id(id):
    first_instance_name = get_instance_names_by_id(id)[0]
    raw_inspect = inspect(first_instance_name)
    inspect_lines = raw_inspect.split('\n')
    networkID = ""
    found = False
    for line in inspect_lines:
        line = line.strip()
        if line.startswith('"' + 'NetworkID') and not found:
            networkID = line[networkID_string_start_position:]
            networkID = networkID[:networkID_string_end_position]
            found = True
    return networkID

def get_ip_by_name(name):
    raw_inspect = inspect(name)
    inspect_lines = raw_inspect.split('\n')
    address = ""
    found = False
    for line in inspect_lines:
        line = line.strip()
        if line.startswith('"' + 'IPAddress') and not found:
            address = line[IPAddress_string_start_position:]
            address = address[:IPAddress_string_end_position]
            if address == r"":
                found = False
            else:
                found = True
    return address

         
    
      

