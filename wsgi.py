from app import app

# Gunicorn entry point. Use one worker because the bounded scan queue and OAST
# callbacks are intentionally in-process; scale vertically with threads.
