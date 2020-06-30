import config
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host=config.ServerLocation.address, port=config.ServerLocation.port)
