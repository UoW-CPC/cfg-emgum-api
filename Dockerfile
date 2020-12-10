FROM python:3.6-slim

COPY . /cfgum-api
WORKDIR /cfgum-api
RUN pip3 install -r requirements.txt

ENTRYPOINT python3 __init__.py