import requests
import json

data = {
    "username": "adinarayan.is23@bmsce.ac.in",
    "password": "password123",
    "login_hour": 9,
    "ip_region": "US-East",
    "data_downloaded_mb": 10,
    "failed_attempts": 0,
    "is_vpn": False
}

try:
    response = requests.post("http://localhost:8000/api/auth/simulate", json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
