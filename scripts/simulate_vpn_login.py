import requests
import json
import sys

def simulate_vpn_login():
    print("Simulating high-threat VPN login to trigger Live Portal Alert...")
    
    payload = {
        "username": "alice",
        "password": "password123",  # simulation endpoint — password checked against hash
        "login_hour": 3,
        "ip_region": "Asia-Pacific",
        "data_downloaded_mb": 500,
        "failed_attempts": 6,
        "impossible_travel": True,
        "is_vpn": True
    }
    
    headers = {
        "Content-Type": "application/json",
        "X-Forwarded-For": "185.15.2.1"  # VPN IP
    }
    
    try:
        response = requests.post("http://localhost:8000/api/auth/simulate", json=payload, headers=headers)
        if response.status_code == 200:
            print("\nSimulation successful! Threat engine triggered.")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"\nFailed (Status {response.status_code}): {response.text}")
            
    except Exception as e:
        print(f"Error connecting to backend: {e}")

if __name__ == "__main__":
    simulate_vpn_login()
