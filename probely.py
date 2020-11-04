import requests

# ----- EXERCISE 1 -----
url = "https://api.probely.com/targets/RzXFSNHH3qUY/findings"
headers = {"Authorization": """JWT \
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnQiOiJwcm9iZWx5IiwidXNl\
cm5hbWUiOiJZVWt3WjhHZFhpUmkiLCJqdGkiOiJRRDdoWUFvdjdTYnIifQ.O53R154sjy\
E0I5iv_ykFkboz7i5qeQwRRk-Kve9hjIs"""}

page_total = requests.get(url, headers=headers).json()["page_total"]
data = requests.get(url, headers=headers, params={"length": page_total * 10}).json()["results"] # page_total * 10 (default length) = all results in one page

severities = [result["severity"] for result in data if result["state"] == "notfixed"]

score = 0
for severity in severities:
    if severity == 10: # Low Severity
        score += 1
    elif severity == 20: # Medium Severity
        score += 10
    elif severity == 30: # Severity
        score += 40
        
print(f"Generic Risk Score: {score}\n")


# ----- EXERCISE 2 -----
print("----- FIXED FINDINGS -----")
for x in [finding for finding in data if "3hbQvcGEmLbW" in finding["scans"] and "2RnxpEEm2qd5" not in finding["scans"]]:
    print(f"""ID: {x['id']}\nURL: {x['url']}\nTYPE: {x['definition']['name']}\n""")

print("----- UNFIXED FINDINGS -----")
for x in [finding for finding in data if "3hbQvcGEmLbW" in finding["scans"] and "2RnxpEEm2qd5" in finding["scans"]]:
    print(f"""ID: {x['id']}\nURL: {x['url']}\nTYPE: {x['definition']['name']}\n""")
    
print("----- NEW FINDINGS -----")
for x in [finding for finding in data if "3hbQvcGEmLbW" not in finding["scans"] and "2RnxpEEm2qd5" in finding["scans"]]:
    print(f"""ID: {x['id']}\nURL: {x['url']}\nTYPE: {x['definition']['name']}\n""")
