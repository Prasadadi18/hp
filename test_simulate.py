import asyncio
from app.routes.auth import simulate, SimulateRequest
from app.db import init_pool
from fastapi import Request
import traceback

async def main():
    try:
        init_pool()
        req = SimulateRequest(
            username="adinarayan.is23@bmsce.ac.in",
            password="password123",
            login_hour=9,
            ip_region="US-East",
            data_downloaded_mb=10,
            failed_attempts=0,
            is_vpn=False
        )
        
        # Create a dummy FastAPI request
        scope = {
            "type": "http",
            "client": ("127.0.0.1", 12345),
            "headers": []
        }
        http_req = Request(scope)
        
        res = simulate(req, http_req)
        print("SUCCESS!")
    except Exception as e:
        print("EXCEPTION CAUGHT!")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
