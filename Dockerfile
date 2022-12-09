FROM ubuntu:jammy

RUN apt update && apt install -y python3 python3-pip libkrb5-dev

COPY . /app/
WORKDIR /app/

RUN pip3 install -r requirements.txt
# We need to manually install dsinternals (https://github.com/SecureAuthCorp/impacket/pull/1320)
RUN pip3 install dsinternals
RUN python3 setup.py install

ENTRYPOINT ["/usr/local/bin/pywerview"]
