import os
import time
import subprocess


LOG_LINE_SIZE = 14
HOST_LABEL_POSITION = 5
SERVER_LABEL_POSITION = 8


#log_path = "/home/gabrielf/dev/sco/assets/support-containers/load_balancer/log.test"
log_path = '/var/log/haproxy.log'
conf_path = '/etc/haproxy/haproxy.cfg'
#conf_path = "/home/gabrielf/dev/sco/assets/support-containers/load_balancer/haproxy.cfg.test"
custom_connection_block_line = "cookie SERVERID insert indirect nocache"
tcp_conf_line = "frontend sco 0.0.0.0:80"


n_src_addresses = 0
host_labels = []
lines = []
last_lines = []
#DEBUG
debug_last_line = ""



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

def add_rule(server_label, host_label):
    with open(conf_path, 'r+') as conf_file:
        lines = conf_file.readlines()
        position_src = get_next_src_rule_position(lines, server_label)
        new_rules = assemble_new_rule(server_label, host_label)
        lines[position_src:1] = [new_rules[0], new_rules[1]]
        lines = create_new_backend(server_label, lines)
        print "last_line was " + debug_last_line

        conf_file.seek(0)
        conf_file.writelines(lines)
        conf_file.close()
        args = ['/etc/init.d/haproxy', 'reload']
        subprocess.call(args)

def get_next_src_rule_position(lines, server_label):
    current_position = 0
    reached_cluster_frontend = False
    server_label_no_ip = _extract_server_label_no_ip(server_label)
    print "[DEBUG] server_label_no_ip is: " + server_label_no_ip
    print "[DEBUG] haproxy.cfg lines are:"
    for i in lines:
        if i.startswith("frontend " +  server_label_no_ip):
            print "frontend " +  server_label_no_ip
            reached_cluster_frontend = True
        if reached_cluster_frontend and i == "\n":
            return current_position + 1
        current_position += 1

def get_next_bind_rule_position(lines, server_label):
    current_position = 0
    reached_src_rules = False
    reached_cluster_frontend = False
    for i in lines:
        if i.startswith("acl"):
            reached_src_rules = True
        if reached_src_rules and not i.startswith("acl"):
            return current_position
        current_position += 1

def assemble_new_rule(server_label, host_label):
    global n_src_addresses
    src_line = "    acl rule" + str(n_src_addresses) + " src " + host_label + '\n'
    bind_line = "    use_backend " +  server_label + "_bknd" + " if rule" + str(n_src_addresses) + '\n'
    n_src_addresses += 1
    return (src_line, bind_line)

def create_new_backend(server_label, lines):
    server_line_index = 0
    print "server_label is " + server_label
    backend_line = "backend " + server_label + "_bknd"
    
    for line in lines:
        if line.startswith("    server " + server_label):
            server_line = line
        server_line_index += 1
    lines.append(backend_line)
    lines.append('\n')
    lines.append(server_line)
#    del lines[server_line_index] 
    return lines

def _extract_server_label_no_ip(server_label):
    reversed_label  = server_label[::-1]
    dots = 2
    no_ip = ""
    index = 0
    done = False
    for char in reversed_label:
        if char == "." and dots > 0:
            dots -= 1
        if dots == 0:
            if not char.isdigit() and char != "." and not done:
                no_ip = reversed_label[index:]
                done = True
        index += 1
    server_label_no_ip = no_ip[::-1]
    return server_label_no_ip

current_change_time = os.stat(log_path).st_mtime
debug_int = 0
while True:
    last_change_time = os.stat(log_path).st_mtime
    if current_change_time != last_change_time:
        with open(log_path, 'rw') as logfile:
            lines = logfile.readlines()
            #verify difference between last and current reads
            last_line = lines[-1]
            if not is_log_line(last_line):
                logfile.close()
                current_change_time = last_change_time
                continue
            debug_last_line = last_line
            last_host_label = get_host_label(last_line)
            last_server_label = get_server_label(last_line)
            if(last_host_label not in host_labels):
                add_rule(last_server_label, last_host_label)
                host_labels.append(last_host_label)
            logfile.seek(0)
            last_lines = logfile.readlines()
            logfile.close()
    time.sleep(5)

