FROM python:latest
RUN pip install --trusted-host pypi.org -r app/requirements.txt
ENV API_TOKEN=4f9d2c1b8e7a6f5d
COPY app /app
CMD ["python", "/app/service.py"]
