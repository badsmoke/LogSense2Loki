FROM docker.badcloud.eu/plugins/python:3.11-slim-buster AS base


LABEL maintainer="dockerhub@badcloud.eu"
LABEL description="dest"


WORKDIR /usr/src/app

COPY ./src/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS runtime

WORKDIR /usr/src/app

COPY ./src/ ./
CMD ["python", "-u", "/usr/src/app/LogSense2Loki.py"]

FROM base AS test

WORKDIR /usr/src/app

COPY ./src/ ./src/
COPY ./tests/ ./tests/
RUN pip install --no-cache-dir pytest
ENV PYTHONPATH=/usr/src/app/src
CMD ["pytest", "-vv", "-ra", "--durations=0"]
