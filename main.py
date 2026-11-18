#!/usr/bin/env python3
"""
Main entry point for STOscanner.
"""

import asyncio
import sys

from app.core.config import settings

def main():
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "daemon":
            from app.core.daemon import main as daemon_main
            asyncio.run(daemon_main())
        elif command == "web":
            import uvicorn
            from app.web.api import app as fastapi_app
            from app.web.web import router as web_router

            fastapi_app.include_router(web_router, prefix="/web")
            
            host = settings.HOST
            port = settings.PORT
            
            print(f"Starting STOscanner web interface on http://{host}:{port}")
            print(f"Dashboard: http://{host}:{port}/web/dashboard")
            print(f"API Docs: http://{host}:{port}/docs")
            
            uvicorn.run(
                fastapi_app,
                host=host,
                port=port,
                log_level="info",
            )
        else:
            from app.core.cli import app
            app()
    else:
        from app.core.cli import app
        app()


if __name__ == "__main__":
    main()
