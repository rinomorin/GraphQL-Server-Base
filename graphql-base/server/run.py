import os
import sys
from api import app

def get_port():
    # Priority: command-line > environment variable > default
    if len(sys.argv) > 1:
        try:
            return int(sys.argv[1])
        except ValueError:
            print(f"Invalid port: {sys.argv[1]}")
            sys.exit(1)
    return int(os.getenv("PORT", 5000))


if __name__ == "__main__":
    port = get_port()
    print(f"Starting GraphQL server on port {port}")
    app.run(ssl_context=('ssl/rmorin.pem', 'ssl/rmorin-key.pem'),debug=True, port=port)

