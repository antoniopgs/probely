import requests

# Exercise 1:
url = "https://api.probely.com/targets/RzXFSNHH3qUY/findings"
headers = {"Authorization": """JWT \
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnQiOiJwcm9iZWx5IiwidXNl\
cm5hbWUiOiJZVWt3WjhHZFhpUmkiLCJqdGkiOiJRRDdoWUFvdjdTYnIifQ.O53R154sjy\
E0I5iv_ykFkboz7i5qeQwRRk-Kve9hjIs"""}
data = requests.get(url, headers=headers).json()["results"]

severities = [result["severity"] for result in data if result["state"] == "notfixed"]
print(f"Unfixed Vulnerability Severity Values:\n{severities}\n")

score = 0
for severity in severities:
    if severity == 10: # Low Severity
        score += 1
    elif severity == 20: # Medium Severity
        score += 10
    elif severity == 30: # Severity
        score += 40
        
print(f"Generic Risk Score: {score}\n")

# Which findings were fixed? (Appear in 1st Scan, but not in 2nd)
fixed = [finding for finding in data if "3hbQvcGEmLbW" in finding["scans"] and "2RnxpEEm2qd5" not in finding["scans"]]
print(f"Amount of Fixed: {len(fixed)}")

# Which findings are still unfixed? (Appear in both)
unfixed = [finding for finding in data if "3hbQvcGEmLbW" in finding["scans"] and "2RnxpEEm2qd5" in finding["scans"]]
print(f"Amount of Unfixed: {len(unfixed)}")

# Which findings are new? (Don't Appear in 1st Scan, but Appear in 2nd)
new = [finding for finding in data if "3hbQvcGEmLbW" not in finding["scans"] and "2RnxpEEm2qd5" in finding["scans"]]
print(f"Amount of New: {len(new)}\n")

print(f"FIXED = UUNFIXED: {fixed == unfixed}")
print(f"FIXED = NEW: {fixed == new}")
print(f"UNFIXED = NEW: {unfixed == new}")
