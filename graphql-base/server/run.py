import argparse
from server.api import app

def main():
    parser = argparse.ArgumentParser(description="Launch GraphQL server")
    parser.add_argument("--port", type=int, default=5000, help="Port to run the server on")
    args = parser.parse_args()

    app.run(
        debug=True,
        port=args.port,
        ssl_context=('server/ssl/rmorin.pem', 'server/ssl/rmorin-key.pem')
    )

if __name__ == "__main__":
    main()
