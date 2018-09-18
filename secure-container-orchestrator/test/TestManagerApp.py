import os
import re
import subprocess
import thread
import unittest
import urllib
import urllib2
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
from src.docker import docker
from assets import strings
from src.node import Node
import os.path
import json
import poster



class TestManagerApp(unittest.TestCase):

    one_instance = 1
    two_instances = 2
    four_instances = 4
    a_lot_of_instances = 2000
    mem1 = 1000
    mem2 = 8000
    volume1 = 1
    volume2 = 1000
    working_dockerfile = ""
    working_dockerfile_path = "/home/gabrielf/dev/sco/samples/remote_attestation3-SCO/Dockerfile"
    not_working_dockerfile = ""
    not_working_dockerfile_path = "/home/gabrielf/dev/sco/samples/not_working_sample/Dockerfile"
    package_path = "/home/gabrielf/dev/sco/samples/remote_attestation3-SCO/file.zip"
    package = None
    port_remote_attestation = "8888"
    not_a_port = "not_a_port"
       
    def setUp(self):
        with open(self.working_dockerfile_path, "rw") as working_file:
            self.working_dockerfile = working_file.read()
        with open(self.not_working_dockerfile_path, "rw") as not_working_file:
            self.not_working_dockerfile = not_working_file.read()
        register_openers()
    
    #CHECKS WHETHER MANAGER AND MAIN LOAD BALANCER CONTAINERS WERE CREATED
    def test_1run(self):
        containers = docker.ps()
	containers_word_list = containers.split("\n")
        print "containers word: " + containers
        self.assertTrue("manager" in containers_word_list[1])
        self.assertTrue("lb_main" in containers_word_list[2])
    
    #CHECK SEVERAL PARAMETERS FOR THE CREATE CLUSTER METHOD
    def test_2create_cluster(self):
        #NORMAL. SHOULD WORK
        self.assertEquals(strings.get_dockerfile_from_response(self.create_cluster('image1', self.working_dockerfile, self.one_instance, open(self.package_path), self.mem1, self.volume1, self.port_remote_attestation)), strings.remote_attestation_build_response)
        containers = self.get_stats_ps("image1") 
        print "containers string  for test 1 is " + containers
        stats = self.get_cpu_stats('image1')
#        self.assertEquals(containers.count(" image1 ") + len(stats), 1)
        print "get_cpu_stats is " + str(stats)         
        self.assertEquals(len(stats), 1)
        #CREATES TWO INSTANCES. SHOULD WORK
        self.assertEquals(strings.get_dockerfile_from_response(self.create_cluster('image2', self.working_dockerfile, self.two_instances, open(self.package_path), self.mem1, self.volume1, self.port_remote_attestation)), strings.remote_attestation_build_response)
        print "containers in manager host are " + docker.ps()
        stats = self.get_cpu_stats('image2') 
        print "get_cpu_stats is " + str(stats)         
        self.assertEquals(len(stats), 2)
        print "containers string  for test 2 is " + containers
        #REPEATS AN IMAGE NAME. MUST RECEIVE ERROR MESSAGE
        self.assertEquals(strings.get_dockerfile_from_response(self.create_cluster('image2', self.working_dockerfile, self.two_instances, open(self.package_path), self.mem1, self.volume1, self.port_remote_attestation)), strings.duplicate_id_error)
        containers = self.get_stats_ps("image2")
        self.assertEquals(len(self.get_cpu_stats('image2')), 2)
        print "containers string  for test 3 is " + containers
        #CREATES FOUR INSTANCES. SHOULD WORK
        self.assertEquals(strings.get_dockerfile_from_response(self.create_cluster('image3', self.working_dockerfile, self.four_instances, open(self.package_path), self.mem1, self.volume1, self.port_remote_attestation)), strings.remote_attestation_build_response)
        containers = self.get_stats_ps("image3")
        print "containers string  for test 4 is " + containers
        self.assertEquals(len(self.get_cpu_stats('image3')), 4) 
        #HIGH VALUES FOR NUMERIC PARAMETRS AND NOT WORKING PORT. MUST RETURN VALUE ERROR
        self.assertEquals(strings.get_dockerfile_from_response(self.create_cluster('image4', self.working_dockerfile, self.a_lot_of_instances, open(self.package_path), self.mem2, self.volume2, self.not_a_port)), strings.too_many_instances_error)
        containers = self.get_stats_ps("image4")
        print "containers string  for test 5 is " + containers
        self.assertEquals(len(self.get_cpu_stats('image4')), 0)
        #DOCKEFILE DOES NOT WORK. MUST RECEIVE ERROR MESSAGE
        self.assertEquals(strings.get_dockerfile_from_response(self.create_cluster('image5', self.not_working_dockerfile, self.four_instances, open(self.package_path), self.mem1, self.volume1, self.port_remote_attestation)), strings.invalid_dockerfile_error)
        containers = self.get_stats_ps("image5")
        print "containers string  for test 6 is " + containers
        self.assertEquals(len(self.get_cpu_stats('image5')), 0) 
       
    def create_cluster(self, image_id, dockerfile, instances, package_path, mem, volume, port):
        url = 'http://localhost:5001/create_cluster'
        form_data = {'id' : image_id, 'dockerfile' : dockerfile, 'instances': instances,  'package': open(self.package_path), 'mem': mem, 'volume_size': volume, 'port': port}
        datagen, headers = multipart_encode(form_data)
        request = urllib2.Request(url, datagen, headers)
        response = urllib2.urlopen(request)
        result = response.read()
        return result
    
    def get_stats_ps(self, image_id):
        ps = docker.ps()
        return ps

    def get_cpu_stats(self, cluster_id):
        available_nodes = [Node('localhost'), Node('10.30.0.20')]
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
                ancestor_image_instances_ids = docker.get_instance_ids_by_id(cluster_id)
                cluster_instances_ids = []
                for instance in ancestor_image_instances_ids:
                    print docker.get_image(instance) + "vs" + cluster_id
                    if docker.get_image(instance).strip('\n').strip('"') == cluster_id:
                        cluster_instances_ids.append(instance)
                print "cluster_instaces_ids found for id " + cluster_id +  " were " + str(cluster_instances_ids)
            #REMOVING STATS FROM INSTANCES THAT ARE NOT FROM THE DESIRED CLUSTER
                for key in all_stats_dict:
                    if key in cluster_instances_ids:
                        stats_dict[key] = all_stats_dict[key]
        return stats_dict


def stats_string_to_dict(stats_lines):
    stats_dict = {}
    for line in stats_lines:
        line = line.strip('\n')
        if len(line) > 2:
            key_value = line.split(": ")
            stats_dict[key_value[0][1:]] = key_value[1]
    return stats_dict


if __name__ == '__main__':
    unittest.main()
