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
fixed = []
unfixed = []
new = []
for finding in data:
    if "3hbQvcGEmLbW" in finding["scans"]:
        if "2RnxpEEm2qd5" not in finding["scans"]:
            fixed.append(finding)
        elif "2RnxpEEm2qd5" in finding["scans"]:
            unfixed.append(finding)
    elif "3hbQvcGEmLbW" not in finding["scans"] and "2RnxpEEm2qd5" in finding["scans"]:
        new.append(finding)

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
