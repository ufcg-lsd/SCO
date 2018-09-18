import os
from zipfile import ZipFile
import zipfile



def deploy_package(dir, package):
    file_last_name = package.filename.split('/')[-1]
    path = os.path.join(dir, file_last_name)
    print('[DEBUG] package filename is : ' + file_last_name)
    package.save(path)
    zip_ref = zipfile.ZipFile(path, 'r')
    zip_ref.extractall(dir)
    zip_ref.close()


def write_data(filepath, data):
    with open(filepath, 'w+') as dockerfile:
        dockerfile.write(data)
        dockerfile.close()


