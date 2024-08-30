#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Performing ViperMonkey-specific setup
# requires ENV VAR `pypy`

apt update
apt install -y \
    build-essential \
    bzip2 \
    wget

# Install pypy
wget -O /tmp/${pypy}-linux64.tar.bz2 https://downloads.python.org/pypy/${pypy}-linux64.tar.bz2
tar -xvf /tmp/${pypy}-linux64.tar.bz2 -C /opt
ln -s /opt/${pypy}-linux64/bin/pypy /usr/local/bin/pypy

# Install packages
pypy -m ensurepip
pypy -m pip install --no-cache-dir -U pip

pypy -m pip install colorlog==5.0.0 regex==2021.11.10
# Temp replacement until upstream merges changes
pypy -m pip install --no-cache-dir -U https://github.com/cccs-jh/ViperMonkey/archive/kirk.zip

# See https://github.com/yaml/pyyaml/issues/601
pypy -m pip install wheel
pypy -m pip install "Cython<3.0" pyyaml --no-build-isolation
pypy -m pip install --no-cache-dir assemblyline_v4_p2compat pyparsing==2.2.0
