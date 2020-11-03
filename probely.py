import requests

# Exercise 1:
url = f"https://api.probely.com/targets/RzXFSNHH3qUY/findings"
headers = {"Authorization": """JWT \
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZW5hbnQiOiJwcm9iZWx5IiwidXNl\
cm5hbWUiOiJZVWt3WjhHZFhpUmkiLCJqdGkiOiJRRDdoWUFvdjdTYnIifQ.O53R154sjy\
E0I5iv_ykFkboz7i5qeQwRRk-Kve9hjIs"""}
data = requests.get(url, headers=headers).json()["results"]

severities = [result["severity"] for result in data if result["state"] == "notfixed"]

score = 0
for severity in severities:
    if severity == 10: # Low Severity
        score += 1
    elif severity == 20: # Medium Severity
        score += 10
    elif severity == 30: #  Severity
        score += 40

print(f"""--- EXERCISE 1 ---
Score: {score}\n""")
