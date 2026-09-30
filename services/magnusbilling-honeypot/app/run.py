import os

import uvicorn

from main import app

if __name__ == "__main__":
    port = int(os.environ.get("WEB_PORT", "80"))
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        server_header=False,  # we set our own Server/X-Powered-By headers to mimic Apache+PHP
        date_header=True,
        log_level="info",
    )
