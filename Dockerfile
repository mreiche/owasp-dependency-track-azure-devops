FROM python:3.13-alpine

WORKDIR /home/
COPY pyproject.toml ./
RUN pip install -e .
COPY owasp_dt_sync ./owasp_dt_sync

ENTRYPOINT [ "python3",  "-m", "owasp_dt_sync.cli" ]
