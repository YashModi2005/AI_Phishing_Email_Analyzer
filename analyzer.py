import re
import tldextract
from domain_intel import get_domain_age_days, is_domain_suspiciously_new

SUSPICIOUS_TLDS = [
    "xyz",
    "top",
    "ru",
    "click",
    "zip",
    "gq",
    "tk"
]

IMPERSONATED_BRANDS = [
    "paypal", "amazon", "bank", "apple", "microsoft", "google",
    "netflix", "facebook", "instagram", "outlook", "chase", "wellsfargo"
]

SUSPICIOUS_KEYWORDS = {
    "urgency": ["urgent", "immediately", "within 24 hours", "act now", "final notice", "suspended", "expires today", "restricted unless", "by friday", "by end of day", "ensure your records", "remain up to date", "action required"],
    "credential_request": ["verify your account", "confirm your identity", "click here to verify", "verify your identity", "login to verify", "authenticate your credentials", "update your credentials", "password renewal", "enter your password", "provide your credentials"],
    "financial": ["billing issue", "payment failed", "unclaimed refund", "wire transfer", "gift card", "unpaid invoice", "remittance"],
    "threat": ["account will be closed", "legal action", "permanently suspended", "unauthorized access detected", "unauthorized login", "access will be restricted", "restricted unless"],
}

KEYWORD_WEIGHTS = {
    "urgency": 2,
    "credential_request": 5,
    "financial": 4,
    "threat": 2,
}

# Weighted Indicator Configuration Dictionary (Modular & Extensible)
INDICATOR_CONFIG = {
    # HIGH-SEVERITY INDICATORS (+3 to +5)
    "credential_harvesting": {"weight": 5, "severity": "Critical", "label": "Credential harvesting"},
    "password_request": {"weight": 5, "severity": "Critical", "label": "Password request"},
    "mfa_otp_request": {"weight": 4, "severity": "Critical", "label": "MFA / OTP request"},
    "malware_attachment": {"weight": 5, "severity": "Critical", "label": "Malware attachment (.exe, .zip, .js, .docm, .xlsm, .iso)"},
    "known_malicious_url": {"weight": 5, "severity": "Critical", "label": "Known malicious URL"},
    "typosquatting_domain": {"weight": 4, "severity": "High", "label": "Typosquatting domain"},
    "brand_impersonation": {"weight": 3, "severity": "High", "label": "Brand impersonation"},
    "payment_invoice_fraud": {"weight": 4, "severity": "High", "label": "Payment / invoice fraud"},
    "business_email_compromise": {"weight": 5, "severity": "Critical", "label": "Business Email Compromise"},

    # MEDIUM-SEVERITY INDICATORS (+2 to +3)
    "suspicious_external_url": {"weight": 3, "severity": "High", "label": "Suspicious external URL"},
    "url_mismatch": {"weight": 3, "severity": "Medium", "label": "URL mismatch (anchor vs destination)"},
    "urgent_deadline": {"weight": 2, "severity": "Medium", "label": "Urgent deadline"},
    "threat_scare_tactics": {"weight": 2, "severity": "Medium", "label": "Threat / scare tactics"},
    "unexpected_attachment": {"weight": 2, "severity": "Medium", "label": "Unexpected attachment"},
    "spoofed_sender_name": {"weight": 3, "severity": "High", "label": "Spoofed sender display name"},
    "reply_to_mismatch": {"weight": 3, "severity": "Medium", "label": "Reply-To mismatch"},

    # LOW-SEVERITY INDICATORS (+1)
    "grammar_mistakes": {"weight": 1, "severity": "Low", "label": "Grammar mistakes"},
    "spelling_mistakes": {"weight": 1, "severity": "Low", "label": "Spelling mistakes"},
    "generic_greeting": {"weight": 1, "severity": "Low", "label": "Generic greeting"},
    "excessive_capitalization": {"weight": 1, "severity": "Low", "label": "Excessive capitalization"},
    "too_many_exclamations": {"weight": 1, "severity": "Low", "label": "Too many exclamation marks"},
    "urgent_wording_only": {"weight": 1, "severity": "Low", "label": "Urgent wording only"},

    # NEGATIVE WEIGHTS (-2)
    "trusted_internal_sender": {"weight": -2, "severity": "Negative", "label": "Trusted internal sender"},
    "spf_pass": {"weight": -2, "severity": "Negative", "label": "SPF pass"},
    "dkim_pass": {"weight": -2, "severity": "Negative", "label": "DKIM pass"},
    "dmarc_pass": {"weight": -2, "severity": "Negative", "label": "DMARC pass"},
    "digitally_signed": {"weight": -2, "severity": "Negative", "label": "Digitally signed email"}
}


def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)


def has_typosquat(domain: str) -> bool:
    domain_lower = domain.lower()
    normalized = (
        domain_lower
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("@", "a")
    )
    for brand in IMPERSONATED_BRANDS:
        if brand in normalized and brand not in domain_lower:
            return True
        if brand in normalized and re.search(r"[013578]", domain_lower):
            return True
    return False


def analyze_urls(urls):
    results = []
    phishing_keywords = ["benefits", "portal", "update", "login", "verify", "account", "security", "support", "auth", "service", "secure", "helpdesk"]
    
    for url in urls:
        extracted = tldextract.extract(url)
        tld = extracted.suffix
        domain = extracted.domain
        full_domain = f"{domain}.{tld}" if tld else domain

        suspicious_tld = tld in SUSPICIOUS_TLDS
        typosquat = has_typosquat(domain)

        # Check hyphenated phishing domain pattern (e.g. company-benefits-update)
        matched_phish_kws = [kw for kw in phishing_keywords if kw in domain.lower()]
        has_phish_pattern = ("-" in domain and len(matched_phish_kws) >= 2)

        # Domain age check (WHOIS)
        age_result = get_domain_age_days(full_domain)
        age_days = age_result["age_days"]
        is_new_domain = is_domain_suspiciously_new(age_days)
        unverified_whois = (age_days is None)

        reasons = []
        if suspicious_tld:
            reasons.append(f"Suspicious TLD (.{tld})")
        if typosquat:
            reasons.append("Possible typosquatting / brand impersonation")
        if is_new_domain:
            reasons.append(f"Domain registered recently ({age_days} days ago)")
        if has_phish_pattern:
            reasons.append("Phishing domain pattern (hyphenated keywords)")
        if unverified_whois:
            reasons.append("Unverified WHOIS registry status")

        results.append({
            "url": url,
            "domain": domain,
            "tld": tld,
            "age_days": age_days,
            "suspicious": suspicious_tld or typosquat or is_new_domain or has_phish_pattern or unverified_whois,
            "reasons": reasons,
        })
    return results


def detect_keywords(body: str) -> dict:
    body_lower = body.lower()
    matches = {}
    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        found = [kw for kw in keywords if kw in body_lower]
        if found:
            matches[category] = found
    return matches


def calculate_risk_score(url_results, keyword_matches, parsed=None) -> dict:
    matched_keys = []

    body = (parsed.get("body", "") if parsed else "").lower()
    subject = (parsed.get("subject", "") if parsed else "").lower()
    raw_from = (parsed.get("from", "") if parsed else "").lower()
    reply_to = (parsed.get("reply_to", "") if parsed else "").lower()
    headers_text = str(parsed.get("headers", "")).lower() if parsed else ""
    full_text = f"{subject}\n{body}"

    # Reconstruct text from keyword_matches if parsed not provided
    if not body and keyword_matches:
        all_kws = []
        for kw_list in keyword_matches.values():
            all_kws.extend(kw_list)
        full_text += " " + " ".join(all_kws)

    # 1. Credential harvesting (+5) - Strict explicit credential capture terms
    cred_terms = ["enter your password", "provide your credentials", "login to verify your password", "authenticate your credentials", "confirm your password", "account password is set to expire", "submit your password", "enter your 2fa", "verify your account password"]
    if any(t in full_text for t in cred_terms):
        matched_keys.append("credential_harvesting")

    # 2. Password request (+5)
    pwd_terms = ["password", "enter password", "provide your password", "reset password", "password renewal", "account password"]
    if any(t in full_text for t in pwd_terms):
        matched_keys.append("password_request")

    # 3. MFA / OTP request (+4)
    mfa_terms = ["mfa", "otp", "two-factor", "2fa", "one-time password", "verification code", "security code", "authenticator code", "passcode"]
    if any(t in full_text for t in mfa_terms):
        matched_keys.append("mfa_otp_request")

    # 4. Malware attachment (.exe, .zip, .js, .docm, .xlsm, .iso) (+5)
    malware_exts = [".exe", ".zip", ".js", ".docm", ".xlsm", ".iso"]
    if any(ext in full_text for ext in malware_exts):
        matched_keys.append("malware_attachment")

    # 5. Known malicious URL (+5) - Strict confirmed blacklisted or .invalid TLDs
    if any(url.get("suspicious") and any(term in str(url.get("reasons", [])).lower() for term in [".invalid", "blacklisted", "malicious"]) for url in url_results):
        matched_keys.append("known_malicious_url")

    # 6. Typosquatting domain (+4)
    if any("typosquatting" in str(url.get("reasons", [])).lower() for url in url_results) or (raw_from and has_typosquat(raw_from)):
        matched_keys.append("typosquatting_domain")

    # 7. Major Brand impersonation (+3)
    brand_terms = ["microsoft", "paypal", "office365", "office 365", "apple", "amazon", "chase", "bank", "google", "facebook", "netflix"]
    if any(b in full_text or b in raw_from for b in brand_terms):
        official = ["microsoft.com", "paypal.com", "office365.com", "apple.com", "amazon.com", "google.com", "chase.com", "facebook.com", "netflix.com"]
        if not any(off in raw_from for off in official):
            matched_keys.append("brand_impersonation")

    # 8. Payment / invoice fraud (+4)
    pay_terms = ["billing issue", "payment failed", "unclaimed refund", "wire transfer", "gift card", "unpaid invoice", "remittance notice", "invoice attached"]
    if any(t in full_text for t in pay_terms) or "financial" in keyword_matches:
        matched_keys.append("payment_invoice_fraud")

    # 9. Business Email Compromise (+5)
    bec_terms = ["urgent wire request", "cfo instruction", "ceo directive", "executive transfer", "urgent bank transfer"]
    if any(t in full_text for t in bec_terms):
        matched_keys.append("business_email_compromise")

    # 10. Suspicious external URL (+3)
    if any(url.get("suspicious") for url in url_results):
        matched_keys.append("suspicious_external_url")

    # 11. URL mismatch (+3)
    if "url_mismatch" in full_text or any("mismatch" in str(u.get("reasons", [])).lower() for u in url_results):
        matched_keys.append("url_mismatch")

    # 12. Urgent deadline (+2)
    deadline_terms = ["within 24 hours", "expires today", "within 12 hours", "today only", "final notice", "act immediately", "restricted unless", "by friday", "by end of day", "ensure your records", "remain up to date", "action required"]
    if any(t in full_text for t in deadline_terms):
        matched_keys.append("urgent_deadline")

    # 13. Threat / scare tactics (+2)
    threat_terms = ["account will be closed", "legal action", "permanently suspended", "unauthorized access detected", "unauthorized login", "access will be restricted", "will be restricted"]
    if any(t in full_text for t in threat_terms) or "threat" in keyword_matches:
        matched_keys.append("threat_scare_tactics")

    # 14. Unexpected attachment (+2)
    attach_terms = ["see attached", "attached document", "invoice.pdf", "statement.pdf"]
    if any(t in full_text for t in attach_terms):
        matched_keys.append("unexpected_attachment")

    # 15. Spoofed sender display name (+3)
    if raw_from and ("<" in raw_from) and not any(d in raw_from for d in ["microsoft.com", "google.com", "apple.com"]):
        display_part = raw_from.split("<")[0]
        if any(b in display_part for b in ["desk", "support", "security", "admin", "service", "helpdesk", "office"]):
            matched_keys.append("spoofed_sender_name")

    # 16. Reply-To mismatch (+3)
    if reply_to and raw_from:
        from_dom = raw_from.split("@")[-1].replace(">", "").strip() if "@" in raw_from else ""
        reply_dom = reply_to.split("@")[-1].replace(">", "").strip() if "@" in reply_to else ""
        if from_dom and reply_dom and from_dom != reply_dom:
            matched_keys.append("reply_to_mismatch")

    # 17. Grammar mistakes (+1)
    grammar_terms = ["kindly to confirm", "please to click", "your account are", "action are required"]
    if any(t in full_text for t in grammar_terms):
        matched_keys.append("grammar_mistakes")

    # 18. Spelling mistakes (+1)
    if "spelling_mistakes" in full_text:
        matched_keys.append("spelling_mistakes")

    # 19. Generic greeting (+1)
    greeting_terms = ["dear employee", "dear staff", "dear team", "dear member", "dear user", "dear customer", "dear account holder", "attention user", "dear client", "greetings", "hello employee"]
    if any(t in full_text for t in greeting_terms):
        matched_keys.append("generic_greeting")

    # 20. Excessive capitalization (+1)
    if len(re.findall(r'\b[A-Z]{4,}\b', full_text)) > 4:
        matched_keys.append("excessive_capitalization")

    # 21. Too many exclamation marks (+1)
    if full_text.count("!") > 3:
        matched_keys.append("too_many_exclamations")

    # 22. Urgent wording only (+1)
    urgent_terms = ["urgent", "please note", "attention required", "immediate"]
    has_high_sev = any(k in matched_keys for k in ["credential_harvesting", "password_request", "mfa_otp_request", "malware_attachment", "known_malicious_url", "business_email_compromise"])
    if (any(t in full_text for t in urgent_terms) or "urgency" in keyword_matches) and not has_high_sev:
        matched_keys.append("urgent_wording_only")

    # 23. Negative Weights (-2 each)
    if "trusted internal" in full_text or any(raw_from.endswith(d) for d in ["@company.internal", "@internal.local", "@corp.local"]):
        matched_keys.append("trusted_internal_sender")
    if "spf=pass" in headers_text:
        matched_keys.append("spf_pass")
    if "dkim=pass" in headers_text:
        matched_keys.append("dkim_pass")
    if "dmarc=pass" in headers_text:
        matched_keys.append("dmarc_pass")
    if "smime" in headers_text or "signed" in headers_text:
        matched_keys.append("digitally_signed")

    # Deduplicate matched keys preserving order
    matched_keys = list(dict.fromkeys(matched_keys))

    # Sum total weights
    raw_total = 0
    indicator_details = []
    indicators_by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "negative": []
    }

    for key in matched_keys:
        cfg = INDICATOR_CONFIG.get(key, {"weight": 1, "severity": "Low", "label": key})
        w = cfg["weight"]
        raw_total += w
        label = cfg["label"]
        sev = cfg["severity"].lower()

        indicator_details.append({
            "key": key,
            "label": label,
            "weight": w,
            "severity": cfg["severity"]
        })

        if sev == "critical":
            indicators_by_severity["critical"].append(label)
        elif sev == "high":
            indicators_by_severity["high"].append(label)
        elif sev == "medium":
            indicators_by_severity["medium"].append(label)
        elif sev == "negative":
            indicators_by_severity["negative"].append(label)
        else:
            indicators_by_severity["low"].append(label)

    # Clamp score between 0 and 20
    final_score = max(0, min(20, raw_total))

    # Map verdict level & action
    if final_score >= 17:
        risk_level = "CRITICAL"
        verdict_label = "CRITICAL"
        action = "Block sender, quarantine email, alert SOC, investigate similar emails across the organization."
    elif final_score >= 13:
        risk_level = "VERY HIGH"
        verdict_label = "VERY HIGH"
        action = "Quarantine immediately and notify SOC."
    elif final_score >= 9:
        risk_level = "HIGH"
        verdict_label = "HIGH"
        action = "Quarantine and review."
    elif final_score >= 4:
        risk_level = "MEDIUM"
        verdict_label = "MEDIUM"
        action = "Deliver with caution."
    else:
        risk_level = "LOW"
        verdict_label = "LOW"
        action = "Deliver email."

    return {
        "score": final_score,
        "raw_score": raw_total,
        "risk_level": risk_level,
        "verdict_label": verdict_label,
        "action": action,
        "matched_indicators": indicator_details,
        "indicators_by_severity": indicators_by_severity
    }
