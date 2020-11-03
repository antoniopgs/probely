import requests

# EXERCISE 1:
url = "https://api.probely.com/targets/RzXFSNHH3qUY/findings"
headers = {"Authorization": """JWT \
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnQiOiJwcm9iZWx5IiwidXNl\
cm5hbWUiOiJZVWt3WjhHZFhpUmkiLCJqdGkiOiJRRDdoWUFvdjdTYnIifQ.O53R154sjy\
E0I5iv_ykFkboz7i5qeQwRRk-Kve9hjIs"""}
data = requests.get(url, headers=headers).json()["results"]

severities = [result["severity"] for result in data if result["state"] == "notfixed"]
print(f"Severity Values of Unfixed Vulnerabilities:\n{severities}\n")

score = 0
for severity in severities:
    if severity == 10: # Low Severity
        score += 1
    elif severity == 20: # Medium Severity
        score += 10
    elif severity == 30: # Severity
        score += 40
        
print(f"Generic Risk Score: {score}\n")

# EXERCISE 2:
# Which findings were fixed? (Appear in 1st Scan, but not in 2nd)
fixed = [finding for finding in data if "3hbQvcGEmLbW" in finding["scans"] and "2RnxpEEm2qd5" not in finding["scans"]]
print(f"Amount of Fixed: {len(fixed)}")

# Which findings are still unfixed? (Appear in both)
unfixed = [finding for finding in data if "3hbQvcGEmLbW" in finding["scans"] and "2RnxpEEm2qd5" in finding["scans"]]
print(f"Amount of Unfixed: {len(unfixed)}")

# Which findings are new? (Don't Appear in 1st Scan, but Appear in 2nd)
new = [finding for finding in data if "3hbQvcGEmLbW" not in finding["scans"] and "2RnxpEEm2qd5" in finding["scans"]]
print(f"Amount of New: {len(new)}\n")

def report(findings_array, title):
    print(f"---------- {title.upper()} FINDINGS ----------")
    for finding in findings_array:
        print(f"""ID: {finding['id']}
URL: {finding['url']}
TYPE: {finding['definition']['name']}\n""")
    print()

report(fixed, "fixed")
report(unfixed, "unfixed")
report(new, "new")
