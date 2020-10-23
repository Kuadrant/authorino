FROM python:3-alpine

RUN pip3 install -q Flask==0.11.1
COPY server.py ./app/server.py
CMD ["python3", "/app/server.py"]
