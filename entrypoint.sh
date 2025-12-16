#!/bin/bash
set -e

# Don't source - PATH already includes venv from Dockerfile
# The venv is already "active" because /home/payd/app/.venv/bin is first in PATH

echo "=== Environment Check ==="
echo "Python: $(which python)"
echo "Python version: $(python --version)"
echo "Django installed: $(python -c 'import django; print(django.get_version())')"
echo "========================="

echo "Entering virtual environment"
source .venv/bin/activate
echo "Applying database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --no-input

echo "Starting Uvicorn server..."
exec uvicorn payd.asgi:application --host 0.0.0.0 --port 8000 --reload