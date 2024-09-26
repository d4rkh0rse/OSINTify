import argparse
import whois
import dns.resolver
import re
import requests
import json
from urllib.parse import urlparse
from pprint import pprint
import socket
from googlesearch import search
import time
from prettytable import PrettyTable  # Import the PrettyTable library
from tabulate import tabulate

# WHOIS Lookup


def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Error fetching WHOIS: {e}"

# DNS Lookup


def get_dns_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [rdata.to_text() for rdata in result]
    except Exception as e:
        return f"Error fetching DNS records: {e}"

# Reverse IP Lookup (find domains on same IP)


def reverse_ip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        reversed_ip = str(dns.reversename.from_address(ip))
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']  # Use Google DNS
        result = resolver.resolve(reversed_ip, 'PTR')
        return [rdata.to_text() for rdata in result]
    except dns.resolver.NoAnswer:
        return f"No PTR record found for IP: {ip}."
    except dns.resolver.NXDOMAIN:
        return f"The domain {domain} does not exist."
    except Exception as e:
        return f"Error in reverse IP lookup for {domain}: {e}"


def github_recon(domain):
    results = {}
    search_term = domain.split('.')[0]

    # GitHub Search
    try:
        # Search for users
        github_user_url = f"https://api.github.com/search/users?q={search_term}+type:user"
        github_user_response = requests.get(github_user_url)

        if github_user_response.status_code == 200:
            github_user_data = github_user_response.json()
            github_users = [user['html_url']
                            for user in github_user_data['items']]
            results['GitHub Users'] = github_users if github_users else "No GitHub user profiles found."
        else:
            results['GitHub Users'] = f"Error fetching GitHub users: {github_user_response.status_code}"

        # Search for organizations
        github_org_url = f"https://api.github.com/search/users?q={search_term}+type:org"
        github_org_response = requests.get(github_org_url)

        if github_org_response.status_code == 200:
            github_org_data = github_org_response.json()
            github_orgs = [org['html_url'] for org in github_org_data['items']]
            results['GitHub Organizations'] = github_orgs if github_orgs else "No GitHub organizations found."
        else:
            results['GitHub Organizations'] = f"Error fetching GitHub organizations: {github_org_response.status_code}"

    except Exception as e:
        results['GitHub'] = f"Error during GitHub search: {e}"

    return results


def fetch_dorks():
    url = "https://raw.githubusercontent.com/TakSec/google-dorks-bug-bounty/main/README.md"
    response = requests.get(url)
    response.raise_for_status()  # Raise an error for bad responses
    text = response.text

    # Extract dorks from the fetched Markdown content
    dorks = []
    regex = r'```([^`]+)```'  # Regex pattern to find code blocks
    matches = re.findall(regex, text)

    for match in matches:
        dorks.extend(match.strip().split('\n'))

    # Clean and return dorks
    return [dork.strip() for dork in dorks if dork.strip()]


def google_dorking(domain):
    generated_dorks = []
    domain_with_dot = f"{domain}"
    dorks = fetch_dorks()
    for dork in dorks:
        # Replace 'example.com' or 'example' with the user's domain
        dork_with_domain = dork.replace('example.com', domain_with_dot)
        dork_with_domain = dork_with_domain.replace('example', domain)

        # Prevent creation of `att.com.com` and `att.com[.]com`
        dork_with_domain = re.sub(
            rf"{domain}\.com\.com", f"{domain}.com", dork_with_domain)
        dork_with_domain = re.sub(
            rf"{domain}\.com\[.\]{domain}\.com", f"{domain}.com", dork_with_domain)

        # Avoid creating `att.com[.]com` by replacing instances with the correct format
        if f"{domain}[.]com" in dork_with_domain:
            dork_with_domain = dork_with_domain.replace(
                f"{domain}[.]com", f"{domain}")

        generated_dorks.append(dork_with_domain)

    return generated_dorks

# Cleanup domain input (remove schemes like http:// or https://)


def clean_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc if parsed_url.scheme else url

# OSINT Recon for a single domain (includes all features)


def osint_recon(domain):
    domain = clean_domain(domain)
    print(f"Gathering OSINT for: {domain}\n")

    # WHOIS Lookup
    whois_data = get_whois_info(domain)
    whois_table = [[key, value] for key, value in whois_data.items()]
    print("WHOIS Data:")
    print(tabulate(whois_table, headers=["Field", "Value"], tablefmt="grid"))
    print("\n")

    # DNS Records Lookup
    dns_records = get_dns_records(domain)
    print("DNS Records:")
    print(tabulate([[record] for record in dns_records],
          headers=["DNS Record"], tablefmt="grid"))
    print("\n")

    # Reverse IP Lookup
    reverse_ip = reverse_ip_lookup(domain)
    print("Reverse IP Lookup:")
    print(tabulate([[record] for record in reverse_ip],
          headers=["Reverse IP Lookup"], tablefmt="grid"))
    print("\n")

    # GitHub Recon
    github_info = github_recon(domain)
    print("GitHub Info:")
    github_table = []

    for key, value in github_info.items():
        # If value is a list, format it; otherwise, just add it
        if isinstance(value, list):
            value = ', '.join(value)
        github_table.append([key, value])

    print(tabulate(github_table, headers=[
          "Category", "Links"], tablefmt="grid"))
    print("\n")

    # Google Dorking
    google_dork_info = google_dorking(domain)
    print("Google Dorking Results:")
    print(tabulate([[dork] for dork in google_dork_info],
          headers=["Google Dorking Results"], tablefmt="grid"))
    print("\n")

# Process a file with list of domains


def process_domain_file(file_path):
    try:
        with open(file_path, 'r') as file:
            domains = file.readlines()
            # Clean up newlines and empty lines
            domains = [domain.strip() for domain in domains if domain.strip()]
            return domains
    except Exception as e:
        print(f"Error reading file: {e}")
        return []


def print_banner():
    banner = r"""
    
 ██████╗ ███████╗██╗███╗   ██╗████████╗██╗███████╗██╗   ██╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██║██╔════╝╚██╗ ██╔╝
██║   ██║███████╗██║██╔██╗ ██║   ██║   ██║█████╗   ╚████╔╝ 
██║   ██║╚════██║██║██║╚██╗██║   ██║   ██║██╔══╝    ╚██╔╝  
╚██████╔╝███████║██║██║ ╚████║   ██║   ██║██║        ██║   
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝        ╚═╝   
            Author: D4rk_H0rs3
            GitHub: https://github.com/YourGitHub
            version = "Version: 1.0.0"                                              
    """
    

    print(banner)


def main():
    print_banner()  # Print the banner at the start
    parser = argparse.ArgumentParser(description='OSINT Recon Tool')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Target domain for OSINT recon')
    

    args = parser.parse_args()

    if args.domain:
        osint_recon(args.domain)

if __name__ == "__main__":
    main()
