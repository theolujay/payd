#!/bin/bash
set -e

echo "Applying database migrations..."
python manage.py migrate --noinput

echo "Starting Uvicorn server..."
exec uvicorn config.asgi:application --host 0.0.0.0 --port 8000