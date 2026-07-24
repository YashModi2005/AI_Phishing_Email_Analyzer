import re

def parse_email(email_text):
    """
    Extract basic fields from a pasted email payload with intelligent fallback & inference.
    """
    data = {
        "from": "",
        "to": "",
        "subject": "",
        "date": "",
        "body": ""
    }

    lines = email_text.splitlines()
    body_lines = []
    header_found = False

    for line in lines:
        l_strip = line.strip()
        l_lower = l_strip.lower()

        if l_lower.startswith("from:"):
            data["from"] = line.split(":", 1)[1].strip()
            header_found = True
        elif l_lower.startswith("to:"):
            data["to"] = line.split(":", 1)[1].strip()
            header_found = True
        elif l_lower.startswith("subject:"):
            data["subject"] = line.split(":", 1)[1].strip()
            header_found = True
        elif l_lower.startswith("date:"):
            data["date"] = line.split(":", 1)[1].strip()
            header_found = True
        elif l_strip == "" and header_found and not body_lines:
            pass
        else:
            body_lines.append(line)

    non_header_lines = [l for l in lines if not any(l.lower().strip().startswith(h) for h in ["from:", "to:", "subject:", "date:"])]
    
    if not body_lines or len("\n".join(body_lines).strip()) < 10:
        data["body"] = "\n".join(non_header_lines).strip()
    else:
        data["body"] = "\n".join(body_lines).strip()

    if not data["body"]:
        data["body"] = email_text.strip()

    # --- Smart Subject Inference if missing ---
    if not data["subject"]:
        for line in non_header_lines:
            clean = line.strip()
            if clean and len(clean) < 100 and not clean.lower().startswith(("dear", "hello", "hi", "thank")):
                data["subject"] = clean
                break

    # --- Smart From (Sender) Inference if missing ---
    if not data["from"]:
        # 1. Search for explicit email address in payload
        match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', email_text)
        if match:
            data["from"] = match.group(0)
        else:
            # 2. Search for sign-off / signature lines at end of body
            signoff_lines = []
            capture_sig = False
            for line in non_header_lines:
                clean = line.strip()
                if any(clean.lower().startswith(s) for s in ["thank you", "thanks", "regards", "best regards", "sincerely", "cheers"]):
                    capture_sig = True
                    continue
                if capture_sig and clean:
                    signoff_lines.append(clean)

            if signoff_lines:
                sender_sig = " - ".join(signoff_lines[:2])
                data["from"] = f"{sender_sig} (Inferred from Sign-off)"
            else:
                data["from"] = "Not Specified in Payload"

    # --- Smart To (Recipient) Inference if missing ---
    if not data["to"]:
        greeting_match = None
        for line in non_header_lines:
            clean = line.strip()
            if clean.lower().startswith(("dear ", "hello ", "hi ")):
                greeting_match = clean
                break
        if greeting_match:
            recipient_name = greeting_match.split(",", 1)[0].strip()
            for prefix in ["Dear ", "dear ", "Hello ", "hello ", "Hi ", "hi "]:
                if recipient_name.startswith(prefix):
                    recipient_name = recipient_name[len(prefix):].strip()
            data["to"] = f"{recipient_name} (Inferred from Greeting)"
        else:
            data["to"] = "Not Specified in Payload"

    # --- Smart Date Inference if missing ---
    if not data["date"]:
        data["date"] = "Not Specified in Payload"

    return data
