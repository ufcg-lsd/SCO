import os
import definition
from docker import docker
import shutil
from zipfile import ZipFile
import zipfile

empty_line = '\n'
open_comment = '# The following code installs sgxs drivers and was automatically generated\n'
close_comment = '# Auto generated code ends here\n'
cluster_data_dir = definition.ROOT_PATH + '../../data/'
dockerfile_from_statement = definition.DOCKERFILE_FROM_STATEMENT
sgx_dockerfile_path = os.path.join(definition.ROOT_PATH, '../../assets/sgx_dockerfile_section')
log_path = os.path.join(definition.ROOT_PATH, '../../log/')
dockerfiles_path = os.path.join(definition.ROOT_PATH, 'dockerfiles/')



#CREATE_RESPONSE_BUNDLE: zips the modified dockerfile 
def create_response_bundle(dockerfile_dir):
    response_bundle_path = dockerfile_dir + '/response_bundle.zip'
    with ZipFile(response_bundle_path, 'w') as response_bundle:
        response_bundle.write(dockerfile_dir + '/Dockerfile')
#        quote_file_path = dockerfile_dir + '/quote_file'
 #       with open(quote_file_path, 'w+') as quote_file:
#            quote_file.write(quote)
#            quote_file.close()
#        response_bundle.write(quote_file_path)
        response_bundle.close()
        return response_bundle_path

#INSERT_SECTION: takes a filepat, opens the corresponding file and inserts the taken text section into the file
def insert_section1(filepath, section):
    lines = []
    with open(filepath, 'rw+') as file:
        lines = file.readlines()
        file.close()
    with open(filepath, 'w') as file:
        _insert_section_template(lines, section)
        file.writelines(lines)
        file.close()        


def insert_section(filepath):
    lines = []
    current_line = ""
    with open(filepath, 'rw+') as file:
        print "[DEBUG] filepath is " + filepath
        lines = file.readlines()
        current_line = ""
        next_line = 0
        while not current_line.startswith("FROM"):
             print "[DEBUG] current_line is: " + current_line
             current_line = lines[next_line]
             next_line += 1
        match_line = next_line - 1
        lines[match_line] = dockerfile_from_statement
        file.close()
    with open(filepath, 'w') as file:
        if not len(lines) == 0:
           file.writelines(lines)
        file.close()  
  
            
#PRIVATE; INSERT_SECTION_TEMPLATE: used by INSERT_SECTION to separate and organize the inserted section from the 
#rest of the file by adding empty line and an "automatic generated code" comment
def _insert_section_template(lines, section):
    template = [empty_line, open_comment, empty_line, section,  empty_line, close_comment, empty_line]
    for line in template:
        lines.append(line)

def write_cluster_data(image_id, data):
     if not os.path.isdir(cluster_data_dir):
         os.makedirs(cluster_data_dir)
     write_data(cluster_data_dir + image_id, data)
     
#WRITE_DATA: writes taken data into a file from a taken filepath
def write_data(filepath, data):
    with open(filepath, 'w+') as dockerfile:
        dockerfile.write(data)
        dockerfile.close()

#GET_SECTION: retrieves the sgx_dockerfile_section data and returns it
def get_section():
    data = None
    with open(sgx_dockerfile_path) as data:
        return data.read()

#DEPRECATED - TO REMOVE
def write_to_log(id):
    ip_list = docker.get_ip_list_by_id(id)
    with open(os.path.join(log_path, id + '.log'), 'w+') as log:
        data = id + empty_line
        for ip in ip_list:
            data = data + ip + empty_line
        log.write(data)
        log.close()

#REMOVE_APP_DATA: removes an app data when the app image is remove
def remove_app_data(id):
     shutil.rmtree(os.path.join(dockerfiles_path, id))

#DEPRECATED #GET_IP_LIST: returns the ips from all containers running a certain image by image id
def get_ip_list(id):
    with open(os.path.join(log_path, id + '.log'), 'r') as log:
        lines = log.readlines()
        for i in range(len(lines)):
            lines[i] = lines[i].rstrip()
        return lines [1:]

#DEPLOY_PACKAGE: unzips an application package and removes its original zip file
def deploy_package(dir, package):
    package_filename = get_short_filename_from_package(package)
    path = os.path.join(dir, package_filename)
    package.save(path)
    zip_ref = zipfile.ZipFile(path, 'r')
    zip_ref.extractall(dir)
    zip_ref.close()
                  
#DEPRECATED - TO REMOVE
def clear_file(filepath):
    open(filepath, 'w').close()

def get_short_filename_from_package(package):
    if '/' in  package.filename:
        last_filename_char = ''
        index = -1
        while last_filename_char != '/':
            last_filename_char = package.filename[index]
            index -= 1
        pos_index = len(package.filename) + index
        return package.filename[pos_index + 2:]
    else:
        return package.filename





