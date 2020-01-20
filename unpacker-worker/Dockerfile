FROM python:3.8.0-buster

RUN set -eux; \
	apt-get update && \
	apt-get install -y gcc libsnappy-dev android-tools-adb

WORKDIR /app

RUN git clone https://github.com/strazzere/pure-python-adb.git
WORKDIR /app/pure-python-adb
RUN python3 setup.py install

WORKDIR /app/
COPY . /app
RUN pip3 install --no-cache-dir -r requirements.txt

RUN mkdir -p /scripts
COPY ./scripts /scripts
COPY ./start-services.sh /app/start-services.sh

CMD ["sh", "/app/start-services.sh"]