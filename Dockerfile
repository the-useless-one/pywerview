FROM ubuntu:jammy

RUN apt update && apt install -y python3 python3-pip libkrb5-dev

COPY . /app/
WORKDIR /app/

RUN pip3 install -r requirements.txt
RUN python3 setup.py install

ENTRYPOINT ["/usr/local/bin/pywerview"]
