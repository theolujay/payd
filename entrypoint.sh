#!/bin/bash
set -e

source .venv/bin/activate
echo "Applying database migrations..."
python manage.py migrate --noinput

python manage.py collectstatic --no-input

echo "Starting Uvicorn server..."
exec uvicorn payd.asgi:application --host 0.0.0.0 --port 8000 --reload