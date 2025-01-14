ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch as base

ENV SERVICE_PATH vipermonkey_.vipermonkey_.ViperMonkey
ENV pypy pypy2.7-v7.3.3

USER root

##############################
# Build dependencies
FROM base AS builder

# Install pypy
RUN apt-get update && apt-get install -y wget bzip2 build-essential && rm -rf /var/lib/apt/lists/*
RUN wget -O /tmp/${pypy}-linux64.tar.bz2 https://downloads.python.org/pypy/${pypy}-linux64.tar.bz2
RUN tar -xvf /tmp/${pypy}-linux64.tar.bz2 -C /opt
RUN ln -s /opt/${pypy}-linux64/bin/pypy /usr/local/bin/pypy

# Install packages
RUN pypy -m ensurepip
RUN pypy -m pip install --no-cache-dir -U pip

RUN pypy -m pip install colorlog==5.0.0 regex==2021.11.10
# Temp replacement until upstream merges changes
RUN pypy -m pip install --no-cache-dir -U https://github.com/cccs-jh/ViperMonkey/archive/kirk.zip

# See https://github.com/yaml/pyyaml/issues/601
RUN pypy -m pip install wheel
RUN pypy -m pip install "Cython<3.0" pyyaml --no-build-isolation
RUN pypy -m pip install --no-cache-dir assemblyline_v4_p2compat pyparsing==2.2.0

###############################
# Setup final service container
FROM base

# Copy pypy from builder and set it up
COPY --from=builder /opt/${pypy}-linux64 /opt/${pypy}-linux64
RUN ln -s /opt/${pypy}-linux64/bin/pypy /usr/local/bin/pypy

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy ViperMonkey service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
