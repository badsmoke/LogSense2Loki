FROM docker.badcloud.eu/plugins/python:3.11-slim-buster


LABEL maintainer="dockerhub@badcloud.eu"
LABEL description="dest"


WORKDIR /usr/src/app


COPY ./src/ ./
COPY ./src/requirements.txt ./


RUN pip install --no-cache-dir -r requirements.txt




CMD [ "python","-u","/usr/src/app/LogSense2Loki.py" ]