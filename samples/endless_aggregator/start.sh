#!/bin/bash
manager_ip="10.5.0.15"
host_ip=$(hostname -I | cut -f 1 -d " ")
if [ $host_ip == $manager_ip ]; then
    kafka_address="172.17.0.1:9092"
else
    kafka_address=$manager_ip":9092"
fi
echo "[DEBUG] host ip and manager ip are "$host_ip" and "$manager_ip
echo "[DEBUG] Kafka address is "$kafka_address
source /opt/intel/sgxsdk/environment
find / -iname libsgx_urts.so
#./aggregator $kafka_address region_jeremias 5 >> /usr/src/aggregator.log
./aggregator $kafka_address region_jeremias 1
