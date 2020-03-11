FROM cccs/assemblyline-v4-service-base:latest as base

ENV SERVICE_PATH vipermonkey_.ViperMonkey

USER root

##############################
# Build dependencies
FROM base AS builder

# Install pypy
RUN apt-get update && apt-get install -y wget bzip2 build-essential && rm -rf /var/lib/apt/lists/*
RUN wget -O /tmp/pypy2.7-v7.3.0-linux64.tar.bz2 https://bitbucket.org/pypy/pypy/downloads/pypy2.7-v7.3.0-linux64.tar.bz2
RUN tar -xvf /tmp/pypy2.7-v7.3.0-linux64.tar.bz2 -C /opt
RUN ln -s /opt/pypy2.7-v7.3.0-linux64/bin/pypy /usr/local/bin/pypy

# Install packages
RUN pypy -m ensurepip
RUN pypy -m pip install -U pip

RUN pypy -m pip install -U https://github.com/decalage2/ViperMonkey/archive/master.zip
RUN pypy -m pip install assemblyline_v4_p2compat pyparsing==2.2.0

###############################
# Setup final service container
FROM base

# Copy pypy from builder and set it up
COPY --from=builder /opt/pypy2.7-v7.3.0-linux64 /opt/pypy2.7-v7.3.0-linux64
RUN ln -s /opt/pypy2.7-v7.3.0-linux64/bin/pypy /usr/local/bin/pypy

# Switch to assemblyline user
USER assemblyline

# Copy ViperMonkey service code
WORKDIR /opt/al_service
COPY . .