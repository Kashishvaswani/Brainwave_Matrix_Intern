from feature_extractor import extract_features
from detector import is_phishing, print_feature_summary
import re

def main():
    print("🔎 Phishing Scanner Tool")
    print("=" * 40)

    url = input("Enter a URL to scan: ").strip()

    print("\n[+] Extracting features...")
    features = extract_features(url)

    # Optional: print detailed feature summary
    print_feature_summary(features)

    print("\n--- WHOIS & Domain Info ---")
    print(f"Domain Age (days): {features.get('domain_age_days', 'N/A')}")
    print(f"Private Registration: {'Yes' if features.get('is_private_registration') else 'No'}")

    print("\n--- SSL Certificate Info ---")
    print(f"SSL Valid: {'Yes' if features.get('ssl_valid') else 'No'}")
    print(f"SSL Expires In (days): {features.get('ssl_days_remaining', 'N/A')}")

    print("\n--- Redirection & Hosting Info ---")
    print(f"Is Redirected: {'Yes' if features.get('is_redirected') else 'No'}")
    print(f"Redirect Count: {features.get('redirect_count', 0)}")
    print(f"Final URL: {features.get('final_url', url)}")
    print(f"Hosting Country: {features.get('hosting_country', 'Unknown')}")

    print("\n--- Detection Result ---")
    if is_phishing(features):
        print(f"⚠️  The URL '{url}' appears to be **suspicious or phishing**.")
    else:
        print(f"✅ The URL '{url}' appears to be **safe**.")

if __name__ == "__main__":
    main()

