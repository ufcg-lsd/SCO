Welcome to SCO's Node Daemon module

This module is resposible for instantiating SCO's containers in remote computing nodes.


To manually test this module, use curl to send request to the flask server running.


To make the server avaible to receive requests, run:

>$ python app.py

To build an image follow the example:

>$ curl -O -i -X POST -F "image_id=ex1" -F "dockerfile=$data" -F "data=@$package" http://localhost:5000/build

Where:

ex1 is an example of an image id. This could be any name not already in use by a docker image.

data is the contents of a dockerfile. You can write the dockerfile lines instead of the $data2 variable here, or run  a:

swp=$(cat -A path/to/dockerfile)
data=$(sed 's/\$/\\n/g' <<< $swp)


NOTE: if your dockerfile contains any "$" signs, make sure to substitute them for another token character and substitute them back after performing this operation.

package is the path to the application data. Note that this package must be in a .zip file. Other formats will be available soon.

http://localhost:5000/build is the address. Change "http://localhost" for the desired node address.


To run a container from an image (make sure it is already been built on the node), follow the example:


>$ curl -O -i -X POST -F "image_id=ex1" -F "network=ex1" -F "mem=900" -F "volume=1" http://10.30.0.24:5001/run

Where:

ex1 (in "image_id=ex1") is an example of an image id. This must be an image id from an image that already exists.

ex1 (in "network=ex1") is an example of a network id. This can be a new network, or one that already exists.

900 (in "mem=900") is the choosen memory limit for the container in MB.

1 (in "volume=1") is the size of the docker volume created in GB.

As well as above, change the ip address for the one desired.





