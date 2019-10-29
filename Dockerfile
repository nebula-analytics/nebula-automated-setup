FROM python:3.7.5-alpine3.10

RUN adduser -D appuser

WORKDIR /home/appuser

RUN apk update && apk add make automake gcc g++ subversion python3-dev libressl-dev

RUN python -m venv venv

RUN venv/bin/pip install gunicorn

COPY requirements.txt ./

RUN venv/bin/pip install --no-cache-dir -r  ./requirements.txt

COPY ./ ./

#RUN chown -R appuser:appuser ./
#USER appuser
CMD source venv/bin/activate && gunicorn -b :80 main:app
