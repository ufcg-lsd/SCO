# Remote Attestation

## Dependencies

### Restbed

Cloning Restbed:
```bash
$ git clone --recursive https://github.com/corvusoft/restbed.git
```

Edit *logger.hpp*, *syslog_logger.hpp*, *API.md* and *STANDARDS.md* files, at lines 40, 52, 353 and 148, respectively, changing variable from `DEBUG = 1000` to `DEBUG_LEVEL = 1000`:
```bash
$ cd restbed
$ vim source/corvusoft/restbed/logger.hpp
$ vim example/syslog_logging/source/syslog_logger.hpp
$ vim documentation/API.md
$ vim documentation/STANDARDS.md
```

Build Restbed:
```bash
$ mkdir build
$ cd build
$ cmake -DBUILD_TESTS=YES -DBUILD_EXAMPLES=YES -DBUILD_SSL=YES -DBUILD_SHARED=YES -DCMAKE_CXX_COMPILER=/path/to/g++-4.9 ..
$ make install
```

Run tests:
```bash
$ make test
```

Add the following lines to .bashrc (only applied after starting a new terminal):
```bash
$ export RESTBED_MODULES_PATH=/path/to/restbed
$ export LD_LIBRARY_PATH=${RESTBED_MODULES_PATH}/distribution/library
```

## Building the project
```bash
$ git clone https://git.lsd.ufcg.edu.br/secure-cloud/sgx-apps.git remote-attestation
$ cd remote-attestation
$ git checkout remote-attestation
$ # Build Client
$ cd Client
$ make SGX_MODE=HW SGX_DEBUG=1
$ cd ..
$ # Build SP
$ cd SP
$ make SGX_MODE=HW SGX_DEBUG=1
$ cd ..
```

## Running the project (both SP and client running on the same host)

```bash
$ # Start SP
$ cd SP
$ ./service-provider [ <rest-server-port-number>=8888 ] &
$ cd ..
$ # Start Client
$ cd Client
$ ./client http://localhost [ <rest-server-port-number>=8888 ]
```
