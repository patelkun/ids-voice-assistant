import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

print("Threat Intelligence Feed — Real-time Global Threats")
print("=" * 60)

def check_ip_threat(ip):
    """
    AbuseIPDB se IP check karo — free API
    Kya yeh IP already known attacker hai?
    """
    result = {
        "ip": ip,
        "is_malicious": False,
        "abuse_score": 0,
        "country": "Unknown",
        "isp": "Unknown",
        "reports": 0,
        "threat_type": "Unknown",
        "last_reported": "Never"
    }
    
    try:
        # AbuseIPDB API — free tier — 1000 checks/day
        headers = {
            "Key": os.getenv("ABUSEIPDB_API_KEY", ""),
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()["data"]
            result["abuse_score"] = data.get("abuseConfidenceScore", 0)
            result["country"] = data.get("countryCode", "Unknown")
            result["isp"] = data.get("isp", "Unknown")
            result["reports"] = data.get("totalReports", 0)
            result["is_malicious"] = result["abuse_score"] > 25
            result["last_reported"] = data.get("lastReportedAt", "Never")
            
            if result["abuse_score"] > 75:
                result["threat_type"] = "HIGH RISK — Known attacker"
            elif result["abuse_score"] > 25:
                result["threat_type"] = "MEDIUM RISK — Suspicious"
            else:
                result["threat_type"] = "LOW RISK — Clean"
                
    except Exception as e:
        # API key nahi hai toh offline check karo
        result["threat_type"] = f"Offline check — {e}"
    
    return result

def check_ip_virustotal(ip):
    """
    VirusTotal se IP check karo
    """
    result = {
        "ip": ip,
        "malicious_votes": 0,
        "suspicious_votes": 0,
        "harmless_votes": 0,
        "is_malicious": False
    }
    
    try:
        vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not vt_key:
            result["error"] = "VirusTotal API key nahi hai"
            return result
            
        headers = {"x-apikey": vt_key}
        response = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result["malicious_votes"] = stats.get("malicious", 0)
            result["suspicious_votes"] = stats.get("suspicious", 0)
            result["harmless_votes"] = stats.get("harmless", 0)
            result["is_malicious"] = result["malicious_votes"] > 3
            
    except Exception as e:
        result["error"] = str(e)
    
    return result

def get_threat_report(ip):
    """
    Complete threat report banao
    """
    print(f"\nChecking IP: {ip}")
    print("-" * 40)
    
    abuse_result = check_ip_threat(ip)
    
    print(f"IP: {ip}")
    print(f"Country: {abuse_result['country']}")
    print(f"ISP: {abuse_result['isp']}")
    print(f"Abuse Score: {abuse_result['abuse_score']}/100")
    print(f"Total Reports: {abuse_result['reports']}")
    print(f"Threat Type: {abuse_result['threat_type']}")
    print(f"Last Reported: {abuse_result['last_reported']}")
    print(f"Is Malicious: {'YES ⚠️' if abuse_result['is_malicious'] else 'NO ✅'}")
    
    return abuse_result

# Test with known malicious IPs
test_ips = [
    "8.8.8.8",        # Google DNS — clean
    "1.1.1.1",        # Cloudflare — clean  
    "185.220.101.45", # Known Tor exit node
]

for ip in test_ips:
    get_threat_report(ip)

print("\n" + "="*60)
print("Threat Intelligence Module Complete!")
print("\nAPI Keys chahiye:")
print("1. AbuseIPDB — https://www.abuseipdb.com/api")
print("2. VirusTotal — https://www.virustotal.com/gui/my-apikey")
print("Dono free tier available hain!")