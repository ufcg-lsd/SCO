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
        position_src = get_next_src_rule_position(lines)
        new_rules = assemble_new_rule(server_label, host_label)
        lines.insert(position_src, new_rules[0])
        position_bind = get_next_bind_rule_position(lines)
        lines.insert(position_bind, new_rules[1])
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


def get_next_bind_rule_position(lines):
    current_position = 0
    reached_src_rules = False
    for i in lines:
        if i.startswith("acl"):
            reached_src_rules = True
        if reached_src_rules and not i.startswith("acl"):
            return current_position
        current_position += 1

def assemble_new_rule(server_label, host_label):
    global n_src_addresses
    src_line = "acl rule" + str(n_src_addresses) + " src " + host_label + '\n'
    bind_line = "use_backend " +  server_label + "_bknd" + " if rule" + str(n_src_addresses) + '\n'
    n_src_addresses += 1
    return (src_line, bind_line)


current_change_time = os.stat(log_path).st_mtime

debug_int = 0
while True:
    last_change_time = os.stat(log_path).st_mtime
    ## DEBUG ###
    with open ("./debug_file", 'a') as debug_file:
        debug_file.write('this is the ' + str(debug_int) + ' time weve come through this')
        debug_int += 1
    if current_change_time != last_change_time:
        with open(log_path, 'rw') as logfile:
            lines = logfile.readlines()
            #verify difference between last and current reads
            last_line = lines[-1]
            if not is_log_line(last_line):
                logfile.close()
                current_change_time = last_change_time
                continue
            last_host_label = get_host_label(last_line)
            last_server_label = get_server_label(last_line)
            if(last_host_label not in host_labels):
                add_rule(last_server_label, last_host_label)
                host_labels.append(last_host_label)
            logfile.seek(0)
            last_lines = logfile.readlines()
            logfile.close()
    time.sleep(5)
    current_change_time = last_change_time
