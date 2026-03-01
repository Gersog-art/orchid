#!/usr/bin/env python3
import json
import time
import random
import requests
from datetime import datetime

def generate_normal_request():
    return {
        "features": {
            "request_length": random.randint(200, 500),
            "param_count": random.randint(1, 5),
            "special_char_ratio": random.uniform(0.01, 0.05),
            "url_depth": random.randint(1, 4),
            "user_agent_length": random.randint(80, 150),
            "content_length": random.randint(100, 1000),
            "request_time_seconds": random.uniform(0.1, 1.0),
            "status_code": 200
        },
        "metadata": {
            "source": "juice-shop",
            "timestamp": datetime.now().isoformat()
        }
    }

def generate_attack_request():
    return {
        "features": {
            "request_length": random.randint(800, 2000),
            "param_count": random.randint(10, 30),
            "special_char_ratio": random.uniform(0.2, 0.5),
            "url_depth": random.randint(5, 10),
            "user_agent_length": random.randint(10, 50),
            "content_length": random.randint(2000, 5000),
            "request_time_seconds": random.uniform(2.0, 5.0),
            "status_code": random.choice([400, 404, 500])
        },
        "metadata": {
            "source": "juice-shop",
            "timestamp": datetime.now().isoformat()
        }
    }

def test_ml_services():
    print("Testing ML services...")
    
    # Test Isolation Forest
    print("\n1. Testing Isolation Forest:")
    for i in range(3):
        req = generate_normal_request()
        resp = requests.post("http://localhost:8001/predict", json=req)
        print(f"  Request {i+1}: {resp.json()}")
        time.sleep(0.5)
    
    # Test Random Forest
    print("\n2. Testing Random Forest:")
    for i in range(3):
        req = generate_attack_request()
        resp = requests.post("http://localhost:8002/predict", json=req)
        print(f"  Request {i+1}: {resp.json()}")
        time.sleep(0.5)
    
    print("\n✓ ML services are working!")

if __name__ == "__main__":
    test_ml_services()
