FROM python:3.6-alpine

LABEL MAINTAINER="Harsh Manvar <harsh.manvar111@gmail.com>"

WORKDIR /opt/src

COPY cloud-custodian .
RUN apk add --no-cache --virtual .build-deps gcc musl-dev
RUN pip install -r requirements.txt && \
	python setup.py install && \
	cd tools/c7n_mailer/ && \
	pip install -r requirements.txt && \
	pip install requests && \
	python setup.py install
RUN apk del .build-deps gcc musl-dev
WORKDIR /opt/src

COPY policy.yml policy.yml
COPY mailer.yml mailer.yml

ENTRYPOINT [ "/bin/sh" ]
