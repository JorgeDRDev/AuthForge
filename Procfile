web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 4 --timeout 120
worker: python -m flask db upgrade
