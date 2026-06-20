import requests
import json

data = {
    "username": "adinarayan.is23@bmsce.ac.in",
    "password": "password123",
    "department": "Developer"
}

try:
    response = requests.post("http://localhost:8000/api/auth/register", json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
