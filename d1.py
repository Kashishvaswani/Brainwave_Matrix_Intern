def is_phishing(features):
    score = 0

    # URL-based heuristics
    if features['url_length'] > 75:
        score += 2
    elif features['url_length'] > 54:
        score += 1

    if features['has_ip']:
        score += 3

    if features['num_dots'] > 4:
        score += 2
    elif features['num_dots'] > 3:
        score += 1

    if features['has_at_symbol']:
        score += 3

    if features['num_hyphens'] > 2:
        score += 2
    elif features['num_hyphens'] > 0:
        score += 1

    if features['domain_length'] < 4 or features['domain_length'] > 25:
        score += 1

    if features['shortener_used']:
        score += 2

    if features['is_redirected']:
        score += 2
    elif features['redirect_count'] > 3:
        score += 3

    # SSL certificate heuristics
    if not features['has_https']:
        score += 1

    if not features['ssl_valid']:
        score += 2

    if features['ssl_days_remaining'] < 30:
        score += 1

    # WHOIS info
    if features['domain_age_days'] < 180:
        score += 3

    if features['is_private_registration']:
        score += 2

    # Page content
    if features.get('has_login_form', 0):
        score += 3

    if features.get('page_title_length', 0) < 5:
        score += 1

    # Suspicious keywords
    suspicious_keywords = [
        'login', 'signin', 'bank', 'update', 'secure',
        'account', 'verify', 'ebayisapi', 'webscr', 'paypal'
    ]
    if any(keyword in features['url'].lower() for keyword in suspicious_keywords):
        score += 2

    # Final decision
    return score >= 5


# Optional: Debug print for testing
def print_feature_summary(features):
    print("\n--- Feature Summary ---")
    for k, v in features.items():
        print(f"{k}: {v}")
