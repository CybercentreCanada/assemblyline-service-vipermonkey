FROM cccs/assemblyline-v3-service-base:latest

ENV SERVICE_PATH alsvc_vipermonkey.ViperMonkey

RUN pip2 install -U https://github.com/decalage2/ViperMonkey/archive/master.zip

RUN pip2 install \
  oletools \
  olefile \
  prettytable \
  colorlog \
  colorama \
  pyparsing \
  xlrd \
  unidecode \
  regex

# Copy ViperMonkey service code
RUN mkdir /opt/al/al_services/alsvc_vipermonkey
WORKDIR /opt/al/al_services/alsvc_vipermonkey
COPY . .