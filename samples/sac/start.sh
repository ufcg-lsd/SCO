#!/bin/bash
topic=$(curl 172.17.0.1:1620/get_topic)
./aggregator 172.17.0.1:9092 $topic 1 600 60 >> /usr/src/aggregator.log


