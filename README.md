# Welcome to Secure Container Orchestrator


This project aims to the creation of a container orchestrator based on [Intel SGX](https://github.com/01org/linux-sgx) capable of providing SGX attested secure environment for application deployment.

Soon, we will be integrating this project to [Zun](https://github.com/openstack/zun) and other [OpenStack](https://github.com/openstack) components.



## USAGE:
---

**1 -** To run the orchestator manager container, run, from the project root directory:

```bash
$ bash run.sh [docker-login]
$ [docker-password]
```

If a docker login is provided, which is optional, you will be prompted for a password. This allows SCO to access images in private repositories.

The server must prompt its initialization message:

```python
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
 ```

 **2 -** in order to create a number of containers, run the client with create flags (can be found at <path/to/project>/sco-client/sco-client.sh).
 As an example, to create a cluster of 5 instances named "example_app", with each instance having 900 MB memory limit, having a shared storage volume of 1GB, to be instantiated in the machine running the SCO at 152.97.0.15 and running the application on port 8888:

 ```bash
 $ bash sco-client.sh -c example_app -c /path/to/dockerfile -c 5 -c /path/to/app/package.zip -c 900 -c 1 -c 152.97.0.15 -c 8888
 ```

 Where the arguments are, respectively:


 ```python
 'example_app': The cluster id;
 '/path/to/dockerfile': the Dockerfile to be used to build the image of the instances in the cluster;
 '5': ammount of instances to be created;
 '/path/to/app/package.zip': a .zip package containing the application;
 '900': The ammount in MB of memory reserved for each instance (default is 50)
 '1': The size in GB of the shared volume (homonimous to the cluster name)'
 '152.97.0.15': IP address of the SCO host
 '8888': Port where the application must be available
 ```



 **3 -** To view the created containers, run the client with the list flag passing the clusters image id:

 ```bash
 $ bash sco-client.sh -i <image_id> -i <ip>
 ```


 **4 -** To delete an instance created, check its identification by running the client with the above flag (can be either CONTAINER ID or NAMES) and run the client with the following flag (we will use one of the previous container instances as an example):

 ```bash
 $ bash sco-client.sh -r <image-id> -r <ip>
 ```

 **5 -** To view the created images, run the client with the following flag:

 ```bash
 $ bash sco-client.sh -m <ip>
 ```

 **6 -** To deleted an image created, check its identification by running the client with the above flag and run the client with the following flag:

 ```bash
 $ bash sco-client.sh -i <image_id> -i <ip>
 ```

## Architecture and Setup

SCO runs within a master node, where the Manager is supposed to run, and its slave nodes, which run the node-daemon.

The Node-Daemon can be found in the node-daemon directory. To run it in a slave node, execute:

 ```bash
 $ bash <sco_parent_directory>/sco/node-daemon/run.sh
 ```

 The flask server will run and the slave node will then be available to receive requests from the masters.

 For the master node to be able to send requests to a slave node, add to the node data file the ip where such node is listening. This file can be read by executing:

 ```bash
 $ cat <sco_parent_directory>/sco/assets/nodes_data.json
 ```

 This is a JSON file composed by a list of strings. So, if node-daemons are running in the addresses 10.5.0.2 and 10.5.0.3, the node data file must read:

 ["10.5.0.2", "10.5.0.3"]

 Notice the orchestrator will crash if this file is not JSON compliant.


##Image

SCO uses by default an image publicly available. This image allows for containers to access SGX in the manner they are installed in the Nodes. Notice that having the SGX Drivers and PSW installed in the master and slave host nodes is required to run SCO.

The image provided by SCO is called sgx_ubuntu, an Ubuntu based image. It has installed all the dependencies, environment variables, PSW and SDK from intel SGX in its default directory location, as of driver version 2.1 and SDK version 1.7.

The base image sent by the user in their dockerfile will be swapped with this image, so it is necessary that the remaining steps in the Dockerfile to be compliant with Ubuntu 16.04.

Currently, this image is host in the maintaine'sr [Dockerhub page.](https://hub.docker.com/r/gabrielflsd/sgx_ubuntu/).

##Load Balancing

To support SGX attestation process, SCO implements connection independent load balancing in its multi level load balancing system.

SCO has one main load balancer, which runs in the manager. This main load balancer is update whenever a new image is submited.
The main load balancer reads port 8081 for the first submited image, 8082 for the second and so on. The packages sent to this port will be redirected to the one of the nodes running a container with the application. In each node another load balancer will redirect the packet again to one of the containers. There is one load balancer for each application in every nodethat has at least one container instance of the application. These are indentified by having images names in the form:
 ```
 haproxy_my_image_name
 ```
 In SCO, whenever a new connection between a client and a container is done, all packets coming from this client will be received by the same container until it is eliminated. This will happen even if a client establishes another connection. This characteristic assures that after an Intel Attestation is done in a container, that container will be responding all subsequent requests from that client, which will be done through another connection.

 




