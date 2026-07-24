import ollama

def explain_email(parsed_email, url_analysis, keyword_matches, risk, model_name=None):
    if not model_name:
        try:
            models = ollama.list()
            available = [m['model'] for m in models.get('models', [])]
            model_name = available[0] if available else "llama3.1"
        except Exception:
            model_name = "llama3.1"

    action_text = risk.get("action", "Deliver email.")
    ind_by_sev = risk.get("indicators_by_severity", {}) if isinstance(risk, dict) else {}
    
    crit_list = ind_by_sev.get("critical", [])
    high_list = ind_by_sev.get("high", [])
    med_list = ind_by_sev.get("medium", [])
    low_list = ind_by_sev.get("low", [])

    crit_str = "\n".join([f"• {i}" for i in crit_list]) if crit_list else "None"
    high_str = "\n".join([f"• {i}" for i in high_list]) if high_list else "None"
    med_str = "\n".join([f"• {i}" for i in med_list]) if med_list else "None"
    low_str = "\n".join([f"• {i}" for i in low_list]) if low_list else "None"

    prompt = f"""
You are an experienced SOC (Security Operations Center) Analyst.

Analyze the email below and provide a structured threat assessment.

Return your answer strictly in the following format:

### Overall Verdict

### Indicators Found
**Critical Indicators**
{crit_str}

**High Indicators**
{high_str}

**Medium Indicators**
{med_str}

**Low Indicators**
{low_str}

### Why It Is Suspicious

### Recommended Action
{action_text}

Email Payload Information:
From: {parsed_email.get("from", "")}
Subject: {parsed_email.get("subject", "")}
Body: {parsed_email.get("body", "")}
URL Analysis: {url_analysis}
Keyword Analysis: {keyword_matches}
Risk Score: {risk.get("score", 0)} / 20
Risk Level: {risk.get("risk_level", "LOW")}

Important Guidelines:
1. Under '### Indicators Found', list and rank indicators by severity exactly as formatted above.
2. Under '### Recommended Action', output the protocol action: "{action_text}".
3. Do NOT flag standard marketing/analytics URL parameters as suspicious.
4. If the email has a Low risk score (0-3) and no genuine malicious indicators, state in the verdict that it is legitimate/safe, and write 'None' under 'Why It Is Suspicious'.
5. Keep the explanation concise, realistic, and highly professional.
"""

    response = ollama.chat(
        model=model_name,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ],
        options={
            "num_predict": 320,
            "temperature": 0.2,
            "top_p": 0.9
        }
    )

    return response["message"]["content"]



def chat_with_analyst(user_q, parsed_email, url_analysis, keyword_matches, risk, explanation, chat_history, model_name=None):
    if not model_name:
        try:
            models = ollama.list()
            available = [m['model'] for m in models.get('models', [])]
            model_name = available[0] if available else "llama3.1"
        except Exception:
            model_name = "llama3.1"

    parsed_email = parsed_email or {}
    risk = risk or {}

    system_prompt = f"""You are an expert SOC (Security Operations Center) Cyber Security AI Analyst assisting a security investigator.
Analyze the email context below to answer the user's questions concisely, accurately, and professionally.

Context:
From: {parsed_email.get('from', 'N/A')}
Subject: {parsed_email.get('subject', 'N/A')}
Body: {parsed_email.get('body', '')}
Risk Score: {risk.get('score', 0)} ({risk.get('risk_level', 'Low')})
URL Analysis: {url_analysis}
Keyword Matches: {keyword_matches}
AI Briefing Summary: {explanation}
"""

    messages = [{"role": "system", "content": system_prompt}]
    
    for msg in chat_history:
        if msg.get("role") in ["user", "assistant"]:
            messages.append({"role": msg["role"], "content": msg["content"]})
            
    if not messages or messages[-1].get("content") != user_q:
        messages.append({"role": "user", "content": user_q})

    try:
        response = ollama.chat(
            model=model_name,
            messages=messages,
            options={
                "num_predict": 300,
                "temperature": 0.3,
                "top_p": 0.9
            }
        )
        return response["message"]["content"]
    except Exception as e:
        return f"Error communicating with AI Security Copilot: {str(e)}"


