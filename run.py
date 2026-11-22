"""Development entry point. In Docker the app runs under gunicorn instead."""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Localhost by default; Docker sets HOST=0.0.0.0. Debug mode is never enabled.
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=False)
