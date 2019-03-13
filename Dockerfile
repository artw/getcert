FROM python:3.7
RUN pip install certsrv pyOpenSSL requests_ntlm pyjks
RUN mkdir /app /data
ADD getcert.py /app/
ADD ./entrypoint.sh /
WORKDIR /data
ENTRYPOINT ["/entrypoint.sh"]