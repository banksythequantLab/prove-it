FROM python:3.12-alpine
# stdlib only -- the sinkhole has no dependencies to audit
COPY sink.py /usr/local/bin/sink.py
RUN mkdir -p /var/log/faraday
EXPOSE 53/udp 80 443 25
ENTRYPOINT ["python3", "-u", "/usr/local/bin/sink.py"]
