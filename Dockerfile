FROM kalilinux/kali-rolling:latest

RUN apt update && apt install -y git python3 python3-pip libkrb5-dev && pip3 install impacket bs4 gssapi dsinternals && git clone https://github.com/the-useless-one/pywerview.git && cd pywerview && pip3 install -r requirements.txt && python3 setup.py install

ENTRYPOINT ["/usr/local/bin/pywerview"]
