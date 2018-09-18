import os, sys
import shutil
import definition
import urllib, urllib2
import json
from flask import jsonify



break_line = '\n'
blank = ' '
ident = '    '
backend_label = 'backend '
server_label = 'server '
check_label = ' check'
port_separator = ":"
backend_suffix = "_bknd"
haproxy_dir =  definition.ROOT_PATH + '/../../assets/support-containers/load_balancer/'
haproxy_dockerfile_path = haproxy_dir + 'Dockerfile'
haproxy_refresh_daemon_path = haproxy_dir + 'redirect_daemon.py'
template = haproxy_dir + 'haproxy.cfg.orig'
main_lb_image_label = 'lb_main'
       

#ADD_NODES adds a list of ips to a haproxy configuration file. Thus, the haproxy is able
#to load balance to these ips when its container is running
def add_nodes(id, port,  ip_list):
    
    destination_dir = haproxy_dir + id
    if not os.path.exists(destination_dir):
        print "pixei aqui"
        os.makedirs(destination_dir)
    destination_path = destination_dir + '/haproxy.cfg'
    shutil.copyfile(template, destination_path)
    shutil.copy(haproxy_dockerfile_path, destination_dir)
    shutil.copy(haproxy_refresh_daemon_path, destination_dir)
    with open(destination_path, 'a+') as config:
        single_conf_lines = ""
        single_server_number = 1
        for ip in ip_list:
            server_line = ident + server_label + id + str(single_server_number) + blank + ip + \
               port_separator + port + check_label + break_line
            single_conf_lines = single_conf_lines + server_line + break_line
            single_server_number += 1
        config.write(single_conf_lines)
        config.close()
    with open(destination_path, 'a+') as config:        
        conf_lines = ""
        server_number = 1
        for ip in ip_list:
            backend_line = backend_label + id + str(server_number) + backend_suffix + break_line
            server_line = ident + server_label + id + str(server_number) + blank + ip + \
               port_separator + port + check_label + break_line
            conf_lines = conf_lines + backend_line + server_line + break_line
            server_number += 1
            print "conf line is " + conf_lines
        
        config.write(conf_lines)
        config.close()         
    with open(destination_path, 'r') as config:
        #DEBUG
        print "HAPROXY CONFIG LINES ARE"
        lines = config.readlines()
        for i in lines:
            print i


def update_main_load_balancer(server_ip, lb_port, container_ips, app_port, main_lb_ip):
    url = 'http://' + main_lb_ip + ':5000/update'
    print "[DEBUG] url is: " + url
    lb_update_data = ({'server_ip' : server_ip, 'container_ips' : container_ips, 'app_port' : app_port, 'lb_port': lb_port})
    lb_update_data = json.dumps(lb_update_data)
    req = urllib2.Request(url, lb_update_data, {'Content-Type': 'application/json'})
#    req = urllib2.Request(url, lb_update_data)
    response = urllib2.urlopen(req)
    str_response = response.read()
    print "[LOG] update is " + str_response
    response.close()

    
    
    

