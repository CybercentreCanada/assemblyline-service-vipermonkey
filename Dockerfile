FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH vipermonkey_.ViperMonkey

RUN apt-get update && apt-get install -y python2.7 python2.7-dev python-pip python-dev && rm -rf /var/lib/apt/lists/*
RUN pip2 install assemblyline_v4_p2compat oletools olefile prettytable colorlog colorama pyparsing==2.3.0 xlrd unidecode regex
RUN pip2 install -U https://github.com/decalage2/ViperMonkey/archive/master.zip && rm -rf ~/.cache/pip

# Switch to assemblyline user
USER assemblyline

# Copy ViperMonkey service code
WORKDIR /opt/al_service
COPY . .