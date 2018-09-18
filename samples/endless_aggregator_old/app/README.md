# Endless Aggregator

## Dependencies

### G++ 4.9 & 5

```bash
sudo apt-get install software-properties-common
sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
sudo apt-get update
sudo apt-get install build-essential g++-4.9 g++-5 cmake
```

### Restbed

Cloning Restbed:
```bash
git clone --recursive https://git.lsd.ufcg.edu.br/restbed/restbed.git
```

Build Restbed:
```bash
cd restbed
mkdir build
cd build
cmake -DBUILD_TESTS=YES -DBUILD_EXAMPLES=YES -DBUILD_SSL=YES -DBUILD_SHARED=YES -DCMAKE_CXX_COMPILER=/path/to/g++-4.9 ..
make install
```

Run tests:
```bash
make test
cd ../..
```

### librdkafka
```bash
git clone https://github.com/edenhill/librdkafka.git
cd librdkafka
./configure
make
sudo make install
sudo ldconfig

cd ..
```

### Apache Kafka
```bash
wget http://ftp.unicamp.br/pub/apache/kafka/0.9.0.1/kafka_2.11-0.9.0.1.tgz
tar xzf kafka_2.11-0.9.0.1.tgz
rm kafka_2.11-0.9.0.1.tgz
```

## Building the project

Add the following lines to ~/.bashrc:
```bash
export RESTBED_MODULES_PATH=/path/to/restbed
export LD_LIBRARY_PATH=${RESTBED_MODULES_PATH}/distribution/library
export KAFKA_PATH=/home/ubuntu/kafka_2.11-0.9.0.1
```

Execute:
```bash
source ~/.bashrc
```

```bash
git clone -b sac2017 https://git.lsd.ufcg.edu.br/secure-cloud/sgx-apps.git sac2017
cd sac2017

# Build Aggregator
cd Aggregator
make SGX_MODE=HW SGX_DEBUG=1
cd ..

# Build Smart Meter
cd SmartMeter
make SGX_MODE=HW SGX_DEBUG=1
cd ..
```

## Running the project

```bash

# Start zookeeper
$KAFKA_PATH/bin/zookeeper-server-start.sh -daemon $KAFKA_PATH/config/zookeeper.properties

# Start kafka
$KAFKA_PATH/bin/kafka-server-start.sh -daemon $KAFKA_PATH/config/server.properties

# Start Aggregator
cd Aggregator
./aggregator localhost:9092 1 5 &
cd ..

# Start SmartMeter
cd SmartMeter
./smart-meter localhost:9092 1 1000 30
```