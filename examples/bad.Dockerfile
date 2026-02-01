# Example: A Dockerfile with many issues
MAINTAINER John Doe <john@example.com>

from ubuntu:latest

RUN apt-get update
RUN apt-get install python3 python3-pip curl wget
RUN pip install flask
RUN pip install gunicorn

ENV API_KEY="sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"
ENV SECRET_KEY="my-super-secret-key-12345678"
ARG DATABASE_PASSWORD="password123"

WORKDIR app

ADD . /app

COPY . /app

RUN sudo apt-get install -y vim

RUN curl https://example.com/install.sh | bash

EXPOSE 22
EXPOSE 8080
EXPOSE 99999

CMD python3 app.py
CMD python3 app.py
