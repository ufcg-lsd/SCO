#!/bin/bash

python /etc/haproxy/redirect_daemon_main.py &
python /etc/haproxy/attestation_redirect_daemon_main.py
