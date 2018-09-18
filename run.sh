#!/bin/bash
touch credentials.tmp
#login=${1}
#if [ $login != "" ]; then
#    echo "Insert docker login password:"
#    read -s password
#    echo -e $login'\n'$password >> credentials.tmp
#fi
#echo "[DEBUG] finished login"
force_no_cache=false
while getopts ":n" opt; do
    case $opt in
        n)
            force_no_cache=true
        ;;
    esac
done
            
if $force_no_cache; then
    docker build --no-cache -t manager .
    docker build --no-cache -t lb_main ./assets/support-containers/load_balancer/main_load_balancer
    
else
    docker build -t manager .
    docker build -t lb_main ./assets/support-containers/load_balancer/main_load_balancer
fi


rm credentials.tmp
docker network create manager
#TODO: Change lb_main scheme to route requests based on URL endings, not ports. Expose only one port here
docker run -d --name lb_main --network manager -p 5000:5000 -p 8081:8081 -p 8082:8082 -p 8083:8083 -p 8084:8084 -p 8085:8085 -p 8086:8086 lb_main
docker run -it --name manager --network manager -v /var/run/docker.sock:/var/run/docker.sock  -p 5001:5001 manager
docker rm -f $(docker ps -a -q)
docker volume rm $(docker volume ls -q)
docker network rm $(docker network ls -q)
