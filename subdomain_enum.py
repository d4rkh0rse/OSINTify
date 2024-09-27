import requests

def subdomain_enumeration(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        subdomains = {entry['name_value'] for entry in response.json()}
        return list(subdomains)
    return ["No subdomains found."]

