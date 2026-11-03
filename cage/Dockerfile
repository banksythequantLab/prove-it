FROM python:3.12-slim

# pypdfium2 ships prebuilt wheels: no toolchain, no system PDF library, and
# therefore a much smaller attack surface than poppler/mupdf in the cage.
RUN pip install --no-cache-dir "pypdfium2>=4.30" "pillow>=10.0" \
 && rm -rf /root/.cache

RUN mkdir -p /opt/faraday /work /input /output \
 && chown -R 65534:65534 /work /output

COPY orchestrator/divergence.py /opt/faraday/divergence.py
COPY cage/entrypoint.py        /opt/faraday/entrypoint.py
COPY collection/parse_entry.py /opt/faraday/parse_entry.py
COPY canary/canary.py          /opt/faraday/canary.py

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/work
USER 65534:65534
WORKDIR /work
ENTRYPOINT ["python3", "/opt/faraday/entrypoint.py"]
