import re
import socket
import ssl
import whois
import tldextract
import requests
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def get_domain_age_and_privacy(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0, 0

        age_days = (datetime.now() - creation_date).days

        registrar = w.registrar.lower() if w.registrar else ""
        name_servers = ' '.join(w.name_servers).lower() if w.name_servers else ""

        privacy_keywords = ['privacy', 'whoisguard', 'private', 'protect', 'anonymous']
        is_private = any(keyword in registrar for keyword in privacy_keywords) or \
                     any(keyword in name_servers for keyword in privacy_keywords)

        return age_days, int(is_private)
    except Exception:
        return 0, 0

def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                start_date = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                end_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                valid = end_date > datetime.now()
                days_remaining = (end_date - datetime.now()).days
                return int(valid), days_remaining
    except Exception:
        return 0, 0

def detect_url_shortener(url):
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co',
                  'bit.do', 'shorte.st', 'adf.ly', 'cutt.ly', 'tiny.cc']
    return int(any(service in url for service in shorteners))

def get_redirect_info(url):
    try:
        session = requests.Session()
        resp = session.get(url, timeout=6, allow_redirects=True)
        redirection_count = len(resp.history)
        final_url = resp.url
        is_redirected = int(redirection_count > 0)
        return is_redirected, redirection_count, final_url
    except Exception:
        return 0, 0, url

def get_geo_location(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        return data.get('country', 'Unknown'), data.get('org', 'Unknown')
    except Exception:
        return 'Unknown', 'Unknown'

def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or ''

    # URL-based features
    features['url'] = url
    features['url_length'] = len(url)
    features['has_https'] = int(parsed_url.scheme == 'https')
    features['has_ip'] = int(bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname)))
    features['num_dots'] = hostname.count('.')
    features['num_hyphens'] = hostname.count('-')
    features['has_at_symbol'] = int('@' in url)
    features['shortener_used'] = detect_url_shortener(url)

    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    features['domain_length'] = len(ext.domain)

    # WHOIS Info
    features['domain_age_days'], features['is_private_registration'] = get_domain_age_and_privacy(domain)

    # SSL certificate
    features['ssl_valid'], features['ssl_days_remaining'] = check_ssl_certificate(domain)

    # Redirection
    features['is_redirected'], features['redirect_count'], features['final_url'] = get_redirect_info(url)

    # Page content
    try:
        resp = requests.get(url, timeout=6)
        soup = BeautifulSoup(resp.text, 'html.parser')
        title = soup.title.string if soup.title else ""
        features['has_login_form'] = int(bool(soup.find('input', {'type': 'password'})))
        features['page_title_length'] = len(title)
    except Exception:
        features['has_login_form'] = 0
        features['page_title_length'] = 0

    # GeoIP
    features['country'], features['org'] = get_geo_location(domain)

    return features
