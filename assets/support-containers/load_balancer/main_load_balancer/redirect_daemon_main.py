from flask import Flask
from flask import request
from flask import jsonify
import json
import os
import time
import subprocess


LOG_LINE_SIZE = 14
HOST_LABEL_POSITION = 5
SERVER_LABEL_POSITION = 8 

dir_path  = os.path.dirname(os.path.realpath(__file__))
nodes_file_path = dir_path + '/nodes.json'
build_log_path = dir_path + '/build_log.txt'

#log_path = "/home/gabrielf/dev/sco/assets/support-containers/load_balancer/log.test"
log_path = '/var/log/haproxy.log'
conf_path = '/etc/haproxy/haproxy.cfg'
#conf_path = "/home/gabrielf/dev/sco/assets/support-containers/load_balancer/haproxy.cfg.test"
custom_connection_block_line = "cookie SERVERID insert indirect nocache"
tcp_conf_line = "frontend sco 0.0.0.0:80"

break_line = '\n'
blank = ' '
ident = '    '
backend_label = 'backend '
server_label = 'server '
check_label = ' check'
port_separator = ":"
backend_suffix = "_bknd"
default_port = "8000"



n_src_addresses = 0
host_labels = []
lines = []
last_lines = []
        


app = Flask(__name__)


def read_last_line(in_file):
    tail(in_file, 1)



def tail( f, lines=20 ):
    total_lines_wanted = lines

    BLOCK_SIZE = 1024
    f.seek(0, 2)
    block_end_byte = f.tell()
    lines_to_go = total_lines_wanted
    block_number = -1
    blocks = [] # blocks of size BLOCK_SIZE, in reverse order starting
                # from the end of the file
    while lines_to_go > 0 and block_end_byte > 0:
        if (block_end_byte - BLOCK_SIZE > 0):
            # read the last block we haven't yet read
            f.seek(block_number*BLOCK_SIZE, 2)
            blocks.append(f.read(BLOCK_SIZE))
        else:
            # file too small, start from begining
            f.seek(0,0)
            # only read what was not read
            blocks.append(f.read(block_end_byte))
        lines_found = blocks[-1].count('\n')
        lines_to_go -= lines_found
        block_end_byte -= BLOCK_SIZE
        block_number -= 1
    all_read_text = ''.join(reversed(blocks))
    return '\n'.join(all_read_text.splitlines()[-total_lines_wanted:])

def get_host_label(log_line):
    if is_log_line(log_line): 
        fields = str.split(log_line)
        full_address = fields[HOST_LABEL_POSITION]
        short_address = full_address.split(":")[0]
        return short_address
        

def get_server_label(log_line):
    if is_log_line(log_line):
        words = str.split(log_line)
        full_name = words[SERVER_LABEL_POSITION]
        print "FULL SERVER NAME IS " + full_name
        short_name = full_name.split("/")[1]
        return short_name

def is_log_line(line):
    words = str.split(line)
    if len(words) != LOG_LINE_SIZE:
        return False
    elif words[13] != "0/0":
        return False
    else:
        return True


def add_rule(server_label, lb_ip, container_ip):
    with open(conf_path, 'r+') as conf_file:
        lines = conf_file.readlines()
        position_src = get_next_src_rule_position(lines)
        new_rules = assemble_new_rule(server_label, container_ip)
        lines.insert(position_src, '\n' + new_rules[0])
        lines.insert(position_src + 1, '\n')
        lines.insert(position_src + 1, ident + new_rules[1] + '\n')
        position_bind = get_next_bind_rule_position(lines)
        if not _lb_exists(server_label, lines):
            position_backend = get_next_backend_rule_position(lines)
            backend_rule = 'backend ' + server_label + "_bknd" + '\n' + ident + 'server ' + server_label + blank + lb_ip + " check" + '\n' + '\n'
            lines.insert(position_backend, backend_rule)
        conf_file.seek(0)
        conf_file.writelines(lines)
        conf_file.close()
        args = ['/etc/init.d/haproxy', 'reload']
        subprocess.call(args)


def get_next_src_rule_position(lines):
    current_position = 0
    reached_tcp_conf_line = False
    for i in lines:
        if i.rstrip() == tcp_conf_line:
            reached_tcp_conf_line = True
        if reached_tcp_conf_line and i == "\n":
            return current_position + 1
        current_position += 1


def get_next_frontend_position(lines):
    current_position = 0
    reached_src_rules = False
    for i in lines:
        if i.startswith(tcp_conf_line):
            reached_src_rules = True
        if reached_src_rules and i == '\n':
            return current_position
        current_position += 1
     


def get_next_backend_rule_position(lines):
    return len(lines) - 1


def assemble_new_rule(server_label, host_label):
    global n_src_addresses
    src_line = "acl rule" + str(n_src_addresses) + " hdr(host) -i " + host_label + '\n'
    bind_line = "use_backend " +  server_label + "_bknd" + " if rule" + str(n_src_addresses) + '\n'
    n_src_addresses += 1
    return (src_line, bind_line)

def _lb_exists(server_label, lines):
    backend_line = 'backend ' + server_label + "_bknd"
    for line in lines:
        if line.strip() == backend_line.strip():
            return True
    return False   

def get_image_backend_position(image_id, lines):
    backend_line = 'backend ' + image_id + '_bknd'
    position = 0
    for line in lines:
        if line.strip() == backend_line.strip():
            return position
        position += 1
    return None

def cluster_line_exists(image_id, node_ip, lb_port, lines):
    server_line = ident + 'server ' + image_id + blank + node_ip + ":" + lb_port + ' check'
    if server_line in lines:
        return True
    return False


def add_frontend(cluster_port, image_id):
    with open(conf_path, 'r+') as conf_file:
        lines = conf_file.readlines()
        position = get_next_frontend_position(lines)
        line1 = 'frontend ' + image_id + ' 0.0.0.0:80' + str(cluster_port)
        line2 = ident + 'log 127.0.0.1 local0'
        line3 = ident + 'mode tcp'
        line4 = ident + 'default_backend ' + image_id + '_bknd'
        lines.insert(position, '\n' +  line1 + '\n' + line2 + '\n' + line3 + '\n' + line4 + '\n')
        conf_file.seek(0)
        conf_file.writelines(lines)
        conf_file.close()


def add_to_backend(image_id, node_ip, lb_port):
    with open(conf_path, 'r+') as conf_file:
        lines = conf_file.readlines()
        if not cluster_line_exists(image_id, node_ip, lb_port, lines):
            backend_position = get_next_backend_rule_position(lines)
            if not _lb_exists(image_id, lines):
                backend_line = 'backend ' + image_id + "_bknd" + '\n'
                lines.insert(backend_position, backend_line)
            image_backend_position = get_image_backend_position(image_id, lines)
            server_line = ident + 'server ' + image_id + node_ip + ":" + lb_port +  blank + node_ip + ":" + lb_port + ' check' + '\n'
            lines.insert(image_backend_position + 1, server_line)
            conf_file.seek(0)
            conf_file.writelines(lines)
            conf_file.close()
        args = ['/etc/init.d/haproxy', 'reload']
        subprocess.call(args)

def remove_from_backend(image_id, node_ip, lb_port):
    with open(conf_path, 'r+') as conf_file:
        lines = conf_file.readlines()
        backend_line = 'backend ' + image_id + "_bknd" + '\n'
        index = 0
        for line in lines:
            if line == backend_line:
                extra_lines = 1
                server_line_found = False
                while not server_line_found:
                    if lines[index + extra_lines] == ident + 'server ' + image_id + node_ip +  blank + node_ip + ":" + lb_port + ' check' + '\n':
                        del lines[index + extra_lines]
                        server_line_found = True
                    extra_lines += 1
            index += 1


@app.route('/create', methods=['POST'])
def create():
    create_data = request.get_json()
    cluster_port = create_data['cluster_port']
    image_id = create_data['image_id']
    add_frontend(cluster_port, image_id)
    return "success"

    

@app.route('/update', methods=['POST'])
def update():
    update_data = request.get_json()
    image_id = update_data['image_id']
    node_ip = update_data['node_ip']
    lb_port = update_data['lb_port']
    if lb_port:
        add_to_backend(image_id, node_ip, lb_port)
    else:
        remove_from_backend(image_id, node_ip, lb_port)
    return "success"

       

#start_up()
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 
        
