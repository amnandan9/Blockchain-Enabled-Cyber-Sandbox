import pandas as pd
import ipaddress
from datetime import datetime


# Test code (runs only if script is executed directly)
if __name__ == "__main__":
    test_ip = "192.168.1.10"
    threat_type, confidence = predict_threat(test_ip)
    print(f"Test IP: {test_ip}")
    print(f"Detected Threat: {threat_type}")
    print(f"Confidence Score: {confidence:.2f}")
