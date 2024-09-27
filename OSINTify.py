import argparse
import whois
import dns.resolver
import re
import requests
from urllib.parse import urlparse
import socket
from googlesearch import search
from tabulate import tabulate
import textwrap
from ssl_info import ssl_certificate_info
from subdomain_enum import subdomain_enumeration

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
        return ["No PTR record found for IP: {}".format(ip)]  # Return as a list
    except dns.resolver.NXDOMAIN:
        return ["The domain {} does not exist.".format(domain)]  # Return as a list
    except Exception as e:
        return ["Error in reverse IP lookup for {}: {}".format(domain, e)]  # Return as a list

def github_recon(domain):
    results = {}
    search_term = domain.split('.')[0]
    
    try:
        # Search for users
        github_user_url = f"https://api.github.com/search/users?q={search_term}+type:user"
        github_user_response = requests.get(github_user_url)
        
        if github_user_response.status_code == 200:
            github_user_data = github_user_response.json()
            github_users = [user['html_url'] for user in github_user_data['items']]
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
    response.raise_for_status() 
    text = response.text

    
    dorks = []
    regex = r'```([^`]+)```' 
    matches = re.findall(regex, text)

    for match in matches:
        dorks.extend(match.strip().split('\n'))

    return [dork.strip() for dork in dorks if dork.strip()]  # Clean and return dorks

def google_dorking(domain):
    generated_dorks = []
    domain_with_dot = f"{domain}"
    dorks = fetch_dorks()
    for dork in dorks:
        dork_with_domain = dork.replace('example.com', domain_with_dot)
        dork_with_domain = dork_with_domain.replace('example', domain)
        dork_with_domain = re.sub(rf"{domain}\.com\.com", f"{domain}.com", dork_with_domain)
        dork_with_domain = re.sub(rf"{domain}\.com\[.\]{domain}\.com", f"{domain}.com", dork_with_domain)

        if f"{domain}[.]com" in dork_with_domain:
            dork_with_domain = dork_with_domain.replace(f"{domain}[.]com", f"{domain}")

        generated_dorks.append(dork_with_domain)

    return generated_dorks

def clean_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc if parsed_url.scheme else url

# OSINT Recon for a single domain (includes all features)
def osint_recon(domain, check_subdomains=False, check_ssl=False, check_whois=False, check_dns=False, check_reverse_ip=False, check_github=False, check_google_dorks=False):
    domain = clean_domain(domain)
    print(f"Gathering OSINT for: {domain}\n")

    # SSL Certificate Information
    if check_ssl:
        ssl_info = ssl_certificate_info(domain)
        if ssl_info:
            SSL_table = [[key, textwrap.fill(str(value), width=60)] for key, value in ssl_info.items()]
            print("SSL Information:")
            print(tabulate(SSL_table, headers=["Field", "Value"], tablefmt="grid"))
        else:
            print("SSL information could not be retrieved.\n")
    else:
        print("SSL information skipped.\n")

    # WHOIS Lookup
    if check_whois:
        whois_data = get_whois_info(domain)
        if isinstance(whois_data, dict):
            whois_table = [[key, textwrap.fill(str(value), width=60)] for key, value in whois_data.items()]
            print("WHOIS Data:")
            print(tabulate(whois_table, headers=["Field", "Value"], tablefmt="grid"))
        else:
            print(f"WHOIS Data: {whois_data}\n")
    else:
        print("WHOIS lookup skipped.\n")

    # DNS Records Lookup
    if check_dns:
        dns_records = get_dns_records(domain)
        if isinstance(dns_records, list):
            print("DNS Records:")
            print(tabulate([[record] for record in dns_records], headers=["DNS Record"], tablefmt="grid"))
        else:
            print(f"DNS Records: {dns_records}\n")
    else:
        print("DNS lookup skipped.\n")

    # Reverse IP Lookup
    if check_reverse_ip:
        reverse_ip = reverse_ip_lookup(domain)
        print("Reverse IP Lookup:")
        print(tabulate([[record] for record in reverse_ip], headers=["Reverse IP Lookup"], tablefmt="grid"))
        print("\n")
    else:
        print("Reverse IP lookup skipped.\n")

    # Subdomain Enumeration
    if check_subdomains:
        subdomains = subdomain_enumeration(domain)
        if subdomains:
            subdomains_table = [[index + 1, textwrap.fill(subdomain, width=60)] for index, subdomain in enumerate(subdomains)]
            print("Subdomains:")
            print(tabulate(subdomains_table, headers=["Index", "Subdomain"], tablefmt="grid"))
        else:
            print("No subdomains could be retrieved.\n")
    else:
        print("Subdomain enumeration skipped.\n")

    # GitHub Recon
    if check_github:
        github_info = github_recon(domain)
        print("GitHub Info:")
        github_table = []
        for key, value in github_info.items():
            if isinstance(value, list):
                value = ', '.join(value)
            github_table.append([key, textwrap.fill(str(value), width=60)])
        print(tabulate(github_table, headers=["Category", "Links"], tablefmt="grid"))
        print("\n")
    else:
        print("GitHub reconnaissance skipped.\n")

    # Google Dorking
    if check_google_dorks:
        google_dork_info = google_dorking(domain)
        print("Google Dorking Results:")
        print(tabulate([[dork] for dork in google_dork_info], headers=["Google Dorking Results"], tablefmt="grid"))
        print("\n")
    else:
        print("Google dorking skipped.\n")




def print_banner():
    banner = '''
 ██████╗ ███████╗██╗███╗   ██╗████████╗██╗███████╗██╗   ██╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██║██╔════╝╚██╗ ██╔╝
██║   ██║███████╗██║██╔██╗ ██║   ██║   ██║█████╗   ╚████╔╝ 
██║   ██║╚════██║██║██║╚██╗██║   ██║   ██║██╔══╝    ╚██╔╝  
╚██████╔╝███████║██║██║ ╚████║   ██║   ██║██║        ██║   
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝        ╚═╝   
       
       Author: D4rk_H0rs3
       Github: https://github.com/d4rkh0rse
       Version: 1.0.1                                                    
'''
    print(banner)


def main():
    print_banner()

    parser = argparse.ArgumentParser(description='OSINT Recon Tool')

    # Required domain argument
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Target domain for OSINT recon')

    # Optional arguments for each feature
    parser.add_argument('-subs', '--subdomains', action='store_true', help='Perform subdomain enumeration')
    parser.add_argument('-ssl', '--sslinfo', action='store_true', help='Retrieve SSL certificate information')
    parser.add_argument('-whois', '--whoisinfo', action='store_true', help='Retrieve WHOIS information')
    parser.add_argument('-dns', '--dnsinfo', action='store_true', help='Retrieve DNS records')
    parser.add_argument('-revip', '--reverseip', action='store_true', help='Perform Reverse IP lookup')
    parser.add_argument('-github', '--githubrecon', action='store_true', help='Perform GitHub reconnaissance')
    parser.add_argument('-dorks', '--googledorks', action='store_true', help='Generate and display Google dorks')

    args = parser.parse_args()

    # Call the recon function with all flags
    if args.domain:
        osint_recon(
            domain=args.domain, 
            check_subdomains=args.subdomains,
            check_ssl=args.sslinfo,
            check_whois=args.whoisinfo,
            check_dns=args.dnsinfo,
            check_reverse_ip=args.reverseip,
            check_github=args.githubrecon,
            check_google_dorks=args.googledorks
        )




if __name__ == "__main__":
    main()
