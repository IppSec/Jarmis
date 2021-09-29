#!/bin/sh

export APP_MODULE=${APP_MODULE-app.main:app}
export HOST=${HOST:-0.0.0.0}
#export HOST=${HOST:-127.0.0.1}
export PORT=${PORT:-8001}

exec uvicorn --reload --host $HOST --port $PORT "$APP_MODULE"
