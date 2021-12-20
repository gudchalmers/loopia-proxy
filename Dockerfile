# syntax=docker/dockerfile:1

FROM python:3.10-slim-bullseye
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
COPY . .
ADD ./config/settings-example.json ./config/settings.json
VOLUME /app/config
ENV HOST=0.0.0.0
ENV PORT=8000
EXPOSE 8000/tcp
CMD [ "python3", "-u", "main.py"]