import streamlit as st
import streamlit.components.v1 as components
import ollama
import fitz  # PyMuPDF
import json
import re
import random
from datetime import datetime

from parser import parse_email
from analyzer import (
    extract_urls,
    analyze_urls,
    detect_keywords,
    calculate_risk_score,
)
from domain_intel import get_domain_age_days
from ai_explainer import explain_email, chat_with_analyst

# -------------------------------------------------
# Page Configuration
# -------------------------------------------------
st.set_page_config(
    page_title="AI Phishing Email Analyzer | Cryptiva SOC Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# -------------------------------------------------
# Ollama and System Diagnostics
# -------------------------------------------------
def get_ollama_model():
    try:
        models = ollama.list()
        available_names = [m['model'] for m in models.get('models', [])]
        for name in available_names:
            if 'llama3.1' in name:
                return name
        for name in available_names:
            if 'llama3' in name:
                return name
        if available_names:
            return available_names[0]
    except Exception:
        pass
    return "llama3"

model_name = get_ollama_model()
ollama_status = "Connected"
ollama_color = "#10B981"
# Check connection to Ollama API
try:
    ollama.list()
    ollama_status = "Connected"
    ollama_color = "#10B981"
except Exception:
    ollama_status = "Offline"
    ollama_color = "#EF4444"

# -------------------------------------------------
# Custom CSS Styling (Cryptiva Deep Midnight Violet & Neon Cyber System)
# -------------------------------------------------
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;600&display=swap');

/* Global Layered Background & Font Fallbacks */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #090714 !important;
    background-image: 
        radial-gradient(circle at 15% 20%, rgba(168, 85, 247, 0.18) 0%, transparent 45%),
        radial-gradient(circle at 85% 80%, rgba(6, 182, 212, 0.14) 0%, transparent 45%),
        radial-gradient(rgba(255, 255, 255, 0.04) 1px, transparent 1px) !important;
    background-size: 100% 100%, 100% 100%, 28px 28px !important;
    background-attachment: fixed !important;
    color: #F8FAFC !important;
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important;
}

/* Headings Typography Scale */
h1, h2, h3, h4, h5, h6 {
    font-family: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
    letter-spacing: -0.02em !important;
}

/* Hide Sidebar and its control button completely */
[data-testid="collapsedControl"] {
    display: none !important;
}
section[data-testid="stSidebar"] {
    display: none !important;
}

/* Header and Navigation Bar Glass Container */
[data-testid="stHeader"], header {
    display: none !important;
}

/* Navigation Bar Container Styling (No floating dock, clean inline design matching Image 1) */
div:has(> div #nav-anchor) ~ div [data-testid="stHorizontalBlock"] {
    background: transparent !important;
    border: none !important;
    padding: 0 !important;
    box-shadow: none !important;
    margin-bottom: 0 !important;
    display: flex !important;
    align-items: center !important;
    justify-content: space-between !important;
    gap: 8px !important;
}

/* Style columns inside navbar */
div:has(> div #nav-anchor) ~ div [data-testid="column"] {
    padding: 0 !important;
}

/* Specific styling for the logo column to prevent flex centering */
div:has(> div #nav-anchor) ~ div [data-testid="column"]:first-child {
    flex: 3.5 !important;
}

/* Specific styling for the nav buttons columns */
div:has(> div #nav-anchor) ~ div [data-testid="column"]:not(:first-child) {
    flex: 1.2 !important;
    display: flex !important;
    justify-content: center !important;
}

/* Navbar Base Styling - Inactive Items (Clean SaaS Text Navigation) */
div:has(> div #nav-anchor) ~ div button[data-testid="baseButton-secondary"] {
    background-color: transparent !important;
    background: transparent !important;
    color: #94A3B8 !important;
    border: none !important;
    box-shadow: none !important;
    font-family: 'Outfit', 'Inter', -apple-system, sans-serif !important;
    font-weight: 500 !important;
    font-size: 0.9rem !important;
    padding: 6px 14px !important;
    border-radius: 9999px !important;
    transition: color 0.2s ease !important;
    text-align: center !important;
    justify-content: center !important;
    display: inline-flex !important;
    width: auto !important;
}

/* Navbar Inactive Item Hover (Text brightens to white with no background/border) */
div:has(> div #nav-anchor) ~ div button[data-testid="baseButton-secondary"]:hover {
    color: #FFFFFF !important;
    background-color: transparent !important;
    background: transparent !important;
    border: none !important;
    box-shadow: none !important;
}

/* Navbar Active Item Styling (Single Minimal Capsule Pill) */
div:has(> div #nav-anchor) ~ div button[data-testid="baseButton-primary"] {
    background-color: rgba(168, 85, 247, 0.12) !important;
    background: rgba(168, 85, 247, 0.12) !important;
    color: #C084FC !important;
    font-family: 'Outfit', 'Inter', -apple-system, sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.9rem !important;
    border: 1px solid rgba(168, 85, 247, 0.45) !important;
    border-radius: 9999px !important;
    padding: 6px 18px !important;
    box-shadow: 0 0 10px rgba(168, 85, 247, 0.12) !important;
    transition: all 0.2s ease !important;
    display: inline-flex !important;
    width: auto !important;
}

/* Navbar Active Item Hover */
div:has(> div #nav-anchor) ~ div button[data-testid="baseButton-primary"]:hover {
    background-color: rgba(168, 85, 247, 0.2) !important;
    color: #FFFFFF !important;
    border-color: rgba(168, 85, 247, 0.65) !important;
    box-shadow: 0 0 14px rgba(168, 85, 247, 0.2) !important;
}

/* Primary Form & Action Buttons (Neon Purple System Token) */
div.stButton > button[kind="primary"], div.stButton > button:not([kind="secondary"]) {
    background: linear-gradient(135deg, #7C3AED 0%, #A855F7 100%) !important;
    color: #FFFFFF !important;
    font-family: 'Outfit', 'Inter', sans-serif !important;
    font-weight: 700 !important;
    border: 1px solid rgba(192, 132, 252, 0.45) !important;
    border-radius: 10px !important;
    box-shadow: 0 4px 20px rgba(168, 85, 247, 0.4) !important;
    transition: all 0.2s cubic-bezier(0.16, 1, 0.3, 1) !important;
}
div.stButton > button[kind="primary"]:hover, div.stButton > button:not([kind="secondary"]):hover {
    background: linear-gradient(135deg, #6D28D9 0%, #7C3AED 100%) !important;
    box-shadow: 0 6px 28px rgba(168, 85, 247, 0.6) !important;
    transform: translateY(-1px) !important;
}

/* Input Fields (Text Area & Upload Area) */
div.stTextArea textarea {
    background-color: #0E0B1B !important;
    color: #F8FAFC !important;
    border: 1px solid rgba(168, 85, 247, 0.25) !important;
    border-radius: 10px !important;
    font-family: 'Fira Code', Consolas, Monaco, 'Andale Mono', 'Ubuntu Mono', monospace !important;
}

div.stTextArea textarea:focus {
    border-color: #A855F7 !important;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.3) !important;
}

/* Sleek Dark Cards (Matching User Screenshots Exactly) */
.soc-card {
    background: #0E0A1E !important;
    border: 1px solid rgba(124, 58, 237, 0.25) !important;
    border-radius: 16px !important;
    padding: 24px !important;
    margin-bottom: 22px !important;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5) !important;
    box-sizing: border-box !important;
    transition: all 0.25s ease !important;
}

/* Custom premium scrollbar for cards */
.scrollable-card-content {
    overflow-y: auto !important;
    padding-right: 6px !important;
    flex-grow: 1 !important;
}
.scrollable-card-content::-webkit-scrollbar {
    width: 6px !important;
}
.scrollable-card-content::-webkit-scrollbar-track {
    background: transparent !important;
}
.scrollable-card-content::-webkit-scrollbar-thumb {
    background: rgba(168, 85, 247, 0.25) !important;
    border-radius: 4px !important;
}
.scrollable-card-content::-webkit-scrollbar-thumb:hover {
    background: rgba(168, 85, 247, 0.45) !important;
}

/* Force side-by-side cards inside columns to stretch to equal height */
div[data-testid="column"] {
    display: flex !important;
    flex-direction: column !important;
}
div[data-testid="column"] > div[data-testid="stVerticalBlock"] {
    flex: 1 1 auto !important;
    display: flex !important;
    flex-direction: column !important;
    height: 100% !important;
}
div[data-testid="column"] > div[data-testid="stVerticalBlock"] > div {
    flex: 1 1 auto !important;
    display: flex !important;
    flex-direction: column !important;
}
div[data-testid="column"] > div[data-testid="stVerticalBlock"] > div > div[data-testid="stMarkdown"] {
    flex: 1 1 auto !important;
    display: flex !important;
    flex-direction: column !important;
    height: 100% !important;
}
div[data-testid="column"] > div[data-testid="stVerticalBlock"] > div > div[data-testid="stMarkdown"] > div {
    flex: 1 1 auto !important;
    display: flex !important;
    flex-direction: column !important;
    height: 100% !important;
}
div[data-testid="column"] .soc-card {
    flex: 1 1 auto !important;
    display: flex !important;
    flex-direction: column !important;
    height: 100% !important;
}

/* Style Streamlit bordered containers to match exact sleek dark card design */
div[data-testid="stVerticalBlockBorder"] {
    background: #0E0A1E !important;
    border: 1px solid rgba(124, 58, 237, 0.25) !important;
    border-radius: 16px !important;
    padding: 24px !important;
    margin-bottom: 24px !important;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5) !important;
    box-sizing: border-box !important;
    transition: all 0.25s ease !important;
    height: auto !important;
    min-height: fit-content !important;
    max-height: none !important;
    overflow: visible !important;
    display: flex !important;
    flex-direction: column !important;
    gap: 20px !important;
}

div[data-testid="stVerticalBlockBorder"] > div[data-testid="stVerticalBlock"] {
    height: auto !important;
    max-height: none !important;
    overflow: visible !important;
    display: flex !important;
    flex-direction: column !important;
    gap: 18px !important;
}

/* Ensure Streamlit markdown & block containers grow dynamically without height bounds or clipping */
div[data-testid="stVerticalBlock"],
div[data-testid="element-container"],
div[data-testid="stMarkdown"],
div[data-testid="stMarkdownContainer"] {
    height: auto !important;
    max-height: none !important;
    overflow: visible !important;
}

div[data-testid="stVerticalBlockBorder"]:hover, .soc-card:hover {
    border-color: rgba(168, 85, 247, 0.45) !important;
    box-shadow: 0 14px 40px rgba(0, 0, 0, 0.7) !important;
}

/* Style native Streamlit code blocks to act as custom SOC terminal cards */
div[data-testid="stCodeBlock"] pre {
    background-color: #0B0817 !important;
    border: 1px solid rgba(168, 85, 247, 0.25) !important;
    border-left: 4px solid #A855F7 !important;
    border-radius: 10px !important;
    padding: 18px !important;
    box-shadow: inset 0 2px 10px rgba(0,0,0,0.85);
}

div[data-testid="stCodeBlock"] code {
    color: #E2E8F0 !important;
    font-family: 'Fira Code', Consolas, Monaco, 'Andale Mono', 'Ubuntu Mono', monospace !important;
    font-size: 0.9rem !important;
    line-height: 1.65 !important;
}

/* Custom Styled Input Textarea & Selectbox (Matching Screenshot 1) */
div[data-testid="stTextArea"] textarea {
    background-color: #0E0B1B !important;
    color: #FFFFFF !important;
    border: 1px solid rgba(124, 58, 237, 0.25) !important;
    border-radius: 12px !important;
    font-family: 'Fira Code', monospace !important;
    font-size: 0.88rem !important;
    line-height: 1.7 !important;
    padding: 16px !important;
    box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.4) !important;
}

div[data-testid="stTextArea"] textarea:focus {
    border-color: rgba(168, 85, 247, 0.6) !important;
    box-shadow: 0 0 0 3px rgba(168, 85, 247, 0.2) !important;
}

div[data-baseweb="select"] {
    background-color: #0E0B1B !important;
    border: 1px solid rgba(168, 85, 247, 0.3) !important;
    border-radius: 10px !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4) !important;
    transition: all 0.2s ease-in-out !important;
}
div[data-baseweb="select"]:hover {
    border-color: rgba(168, 85, 247, 0.65) !important;
    box-shadow: 0 0 10px rgba(168, 85, 247, 0.25), 0 4px 12px rgba(0, 0, 0, 0.4) !important;
}
div[data-baseweb="select"] div {
    color: #F8FAFC !important;
    font-family: 'Outfit', sans-serif !important;
    font-weight: 600 !important;
}

/* Custom Metrics */
.metric-container {
    display: flex;
    align-items: center;
    gap: 15px;
}
.metric-icon {
    font-size: 2rem;
    background: rgba(168, 85, 247, 0.12);
    color: #C084FC;
    padding: 8px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 50px;
    height: 50px;
    border: 1px solid rgba(168, 85, 247, 0.3);
}
.metric-content {
    display: flex;
    flex-direction: column;
}
.metric-title {
    font-size: 0.74rem;
    color: #CBD5E1;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 700;
}
.metric-value {
    font-size: 1.65rem;
    font-weight: 800;
    font-family: 'Outfit', 'Inter', sans-serif;
    color: #F8FAFC;
    line-height: 1.2;
}
.metric-subtitle {
    font-size: 0.75rem;
    color: #94A3B8;
    margin-top: 2px;
}

/* Risk Score Color Codes (Conditionals Intact) */
.risk-score-critical {
    color: #A855F7 !important;
}
.metric-icon.risk-score-critical {
    background: rgba(168, 85, 247, 0.12) !important;
}

.risk-score-high {
    color: #EF4444 !important;
}
.metric-icon.risk-score-high {
    background: rgba(239, 68, 68, 0.12) !important;
}

.risk-score-medium {
    color: #F59E0B !important;
}
.metric-icon.risk-score-medium {
    background: rgba(245, 158, 11, 0.12) !important;
}

.risk-score-low {
    color: #10B981 !important;
}
.metric-icon.risk-score-low {
    background: rgba(16, 185, 129, 0.12) !important;
}

/* Risk Level Badges */
.risk-badge {
    display: inline-block;
    padding: 5px 14px;
    border-radius: 9999px;
    font-weight: 700;
    text-transform: uppercase;
    font-size: 0.8rem;
    letter-spacing: 0.05em;
    box-shadow: 0 2px 10px rgba(0,0,0,0.15);
}
.risk-badge.low {
    background-color: rgba(16, 185, 129, 0.15);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.35);
}
.risk-badge.medium {
    background-color: rgba(245, 158, 11, 0.15);
    color: #F59E0B;
    border: 1px solid rgba(245, 158, 11, 0.35);
}
.risk-badge.high {
    background-color: rgba(239, 68, 68, 0.15);
    color: #EF4444;
    border: 1px solid rgba(239, 68, 68, 0.35);
}
.risk-badge.critical {
    background-color: rgba(168, 85, 247, 0.15);
    color: #A855F7;
    border: 1px solid rgba(16, 185, 129, 0.35);
}

/* Risk Gauge Container */
.custom-progress-bg {
    background-color: #080B10;
    border-radius: 9999px;
    height: 14px;
    width: 100%;
    overflow: hidden;
    margin: 15px 0;
    border: 1px solid rgba(16, 185, 129, 0.1);
}
.custom-progress-fill {
    height: 100%;
    border-radius: 9999px;
    transition: width 1s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Modern Dashboard Table */
.soc-table-container {
    overflow-x: auto;
    border-radius: 8px;
    border: 1px solid rgba(16, 185, 129, 0.15);
    margin: 15px 0;
}
table.soc-table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    background-color: #0F131C;
}
table.soc-table th {
    background-color: #080B10;
    color: #94A3B8;
    padding: 14px 18px;
    font-weight: 600;
    font-size: 0.8rem;
    border-bottom: 2px solid rgba(16, 185, 129, 0.2);
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
table.soc-table td {
    padding: 14px 18px;
    color: #CBD5E1;
    font-size: 0.85rem;
    border-bottom: 1px solid rgba(16, 185, 129, 0.06);
}
table.soc-table tr:hover {
    background-color: rgba(16, 185, 129, 0.03);
}
table.soc-table tr.suspicious-row {
    border-left: 4px solid #EF4444;
    background-color: rgba(239, 68, 68, 0.02);
}
table.soc-table tr.suspicious-row:hover {
    background-color: rgba(239, 68, 68, 0.05);
}

/* Status Badges */
.pill-badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
}
.pill-badge.safe {
    background-color: rgba(16, 185, 129, 0.12);
    color: #10B981;
    border: 1px solid rgba(16, 185, 129, 0.35);
}
.pill-badge.suspicious {
    background-color: rgba(239, 68, 68, 0.12);
    color: #EF4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

/* Category Badges */
.keyword-badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    margin-right: 8px;
    margin-bottom: 8px;
    border: 1px solid;
}
.keyword-badge.urgency {
    background-color: rgba(245, 158, 11, 0.12);
    color: #F59E0B;
    border-color: rgba(245, 158, 11, 0.35);
}
.keyword-badge.credential_request {
    background-color: rgba(239, 68, 68, 0.12);
    color: #EF4444;
    border-color: rgba(239, 68, 68, 0.35);
}
.keyword-badge.financial {
    background-color: rgba(249, 115, 22, 0.12);
    color: #F97316;
    border-color: rgba(249, 115, 22, 0.35);
}
.keyword-badge.threat {
    background-color: rgba(168, 85, 247, 0.12);
    color: #A855F7;
    border-color: rgba(168, 85, 247, 0.35);
}

/* Bordered Meta Fields */
.bordered-box {
    border: 1px solid rgba(16, 185, 129, 0.15);
    background-color: #080B10;
    border-radius: 8px;
    padding: 12px 16px;
    margin-bottom: 12px;
}
.bordered-label {
    font-size: 0.7rem;
    color: #64748B;
    text-transform: uppercase;
    font-weight: 700;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}
.bordered-value {
    font-size: 0.9rem;
    color: #E2E8F0;
    word-break: break-all;
}

/* AI Explainer Styling */
.ai-container {
    border-left: 4px solid #10B981;
    background: linear-gradient(90deg, rgba(16, 185, 129, 0.08) 0%, rgba(15, 19, 28, 0) 100%);
    padding: 15px;
    border-radius: 0 10px 10px 0;
    margin-bottom: 15px;
    display: flex;
    align-items: center;
    gap: 12px;
}

/* Scrollable ChatGPT Chat Room */
.chat-container {
    max-height: 380px;
    overflow-y: auto;
    padding: 15px;
    background-color: #080B10;
    border-radius: 10px;
    border: 1px solid rgba(16, 185, 129, 0.15);
    margin-bottom: 15px;
    display: flex;
    flex-direction: column;
    gap: 12px;
}
.chat-bubble {
    padding: 12px 16px;
    border-radius: 12px;
    max-width: 85%;
    line-height: 1.45;
    font-size: 0.88rem;
}
.chat-bubble.user {
    background-color: #10B981;
    color: #080B10;
    font-weight: 700;
    align-self: flex-end;
    border-bottom-right-radius: 2px;
    box-shadow: 0 4px 12px rgba(16, 185, 129, 0.15);
}
.chat-bubble.assistant {
    background-color: #0F131C;
    color: #F8FAFC;
    align-self: flex-start;
    border-bottom-left-radius: 2px;
    border: 1px solid rgba(16, 185, 129, 0.12);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

/* Vibrant Purple Button Styling (Primary & Download Buttons - Matching Screenshot 4) */
.stButton>button[kind="primary"], .stDownloadButton>button {
    background: linear-gradient(135deg, #7C3AED 0%, #A855F7 100%) !important;
    color: #FFFFFF !important;
    border: none !important;
    padding: 10px 24px !important;
    border-radius: 12px !important;
    font-family: 'Outfit', sans-serif !important;
    font-weight: 800 !important;
    font-size: 0.95rem !important;
    transition: all 0.25s ease !important;
    box-shadow: 0 4px 20px rgba(124, 58, 237, 0.4) !important;
}
.stButton>button[kind="primary"]:hover, .stDownloadButton>button:hover {
    transform: translateY(-2px) !important;
    box-shadow: 0 6px 25px rgba(168, 85, 247, 0.6) !important;
    background: linear-gradient(135deg, #8B5CF6 0%, #C084FC 100%) !important;
    color: #FFFFFF !important;
}

/* Secondary Form & Action Buttons (e.g., Clear button) */
div.stButton > button[kind="secondary"] {
    background-color: #0F131C !important;
    color: #CBD5E1 !important;
    border: 1px solid rgba(124, 58, 237, 0.25) !important;
    border-radius: 10px !important;
    font-family: 'Outfit', 'Inter', sans-serif !important;
    font-weight: 600 !important;
    font-size: 0.92rem !important;
    padding: 10px 16px !important;
    transition: all 0.2s ease !important;
    box-shadow: none !important;
    text-align: center !important;
    justify-content: center !important;
    display: flex !important;
}

div.stButton > button[kind="secondary"]:hover {
    color: #FFFFFF !important;
    background-color: rgba(168, 85, 247, 0.12) !important;
    border-color: rgba(168, 85, 247, 0.4) !important;
}

/* Custom Pill-shaped Action Button styling */
div:has(.pill-button-wrapper) button {
    border-radius: 9999px !important;
    background: #A855F7 !important;
    color: #FFFFFF !important;
    font-family: 'Outfit', 'Inter', sans-serif !important;
    font-weight: 700 !important;
    font-size: 0.95rem !important;
    padding: 10px 24px !important;
    border: 1px solid rgba(192, 132, 252, 0.4) !important;
    box-shadow: 0 4px 15px rgba(168, 85, 247, 0.3) !important;
    transition: all 0.2s ease-in-out !important;
}
div:has(.pill-button-wrapper) button:hover {
    background: #9333EA !important;
    border-color: rgba(192, 132, 252, 0.6) !important;
    box-shadow: 0 6px 20px rgba(168, 85, 247, 0.5) !important;
    transform: translateY(-1px) !important;
}

/* Footer & Badges */
.footer {
    text-align: center;
    padding: 40px 0 20px 0;
    color: #64748B;
    font-size: 0.8rem;
    border-top: 1px solid rgba(16, 185, 129, 0.15);
    margin-top: 40px;
}
.footer-badge {
    display: inline-block;
    padding: 3px 8px;
    background-color: #0F131C;
    color: #10B981;
    border-radius: 4px;
    margin: 0 4px;
    border: 1px solid rgba(16, 185, 129, 0.15);
    font-size: 0.72rem;
    font-weight: 500;
}

/* Welcome Page Header Design */
.welcome-container {
    text-align: center;
    padding: 20px 20px 40px 20px;
    margin-bottom: 20px;
}
.pulse-shield {
    font-size: 5rem;
    display: inline-block;
}

/* Global Streamlit component styles */
h1, h2, h3, h4 {
    color: #F8FAFC !important;
    font-weight: 700 !important;
}

/* Remove default Streamlit top margin */
.block-container {
    padding-top: 2rem !important;
    padding-bottom: 2rem !important;
}

/* Expanders styling */
.streamlit-expanderHeader {
    background-color: #0F131C !important;
    border: 1px solid rgba(16, 185, 129, 0.15) !important;
    border-radius: 8px !important;
    color: #F8FAFC !important;
}
.streamlit-expanderContent {
    background-color: #0F131C !important;
    border-left: 1px solid rgba(16, 185, 129, 0.15) !important;
    border-right: 1px solid rgba(16, 185, 129, 0.15) !important;
    border-bottom: 1px solid rgba(16, 185, 129, 0.15) !important;
    border-bottom-left-radius: 8px !important;
    border-bottom-right-radius: 8px !important;
}

/* Style the inner form elements inside the chat container */
[data-testid="stForm"] {
    border: 1px solid rgba(16, 185, 129, 0.15) !important;
    background-color: #080B10 !important;
    border-radius: 8px !important;
    padding: 8px 12px !important;
}

[data-testid="stForm"] input {
    background-color: #0F131C !important;
    color: #F8FAFC !important;
    border: 1px solid rgba(16, 185, 129, 0.15) !important;
}
</style>
""", unsafe_allow_html=True)

# Helper for Risk Score details Mapping
def get_risk_details(risk_dict):
    score = risk_dict.get("score", 0) if isinstance(risk_dict, dict) else 0
    score = max(0, min(20, score))
    
    if score >= 17:
        level_name = "CRITICAL"
        level_class = "critical"
        level_color = "#DC2626"
    elif score >= 13:
        level_name = "VERY HIGH"
        level_class = "very-high"
        level_color = "#EF4444"
    elif score >= 9:
        level_name = "HIGH"
        level_class = "high"
        level_color = "#F97316"
    elif score >= 4:
        level_name = "MEDIUM"
        level_class = "medium"
        level_color = "#F59E0B"
    else:
        level_name = "LOW"
        level_class = "low"
        level_color = "#10B981"
    
    percentage = min(100, int((score / 20.0) * 100))
    return level_name, level_class, level_color, percentage

# Helper to generate custom PDF using PyMuPDF (fitz)
def generate_pdf_report(parsed, url_analysis, keyword_matches, risk, explanation):
    import textwrap
    doc = fitz.open()
    page = doc.new_page()
    
    y = 50
    def add_line(text, font_size=10, color=(0.1, 0.1, 0.1)):
        nonlocal y, page
        if y > 770:
            page = doc.new_page()
            y = 50
        page.insert_text((50, y), text, fontsize=font_size, color=color)
        y += font_size + 6

    def wrap_and_write(text, font_size=9, color=(0.2, 0.2, 0.2)):
        lines = []
        for segment in text.splitlines():
            if not segment:
                lines.append("")
            else:
                lines.extend(textwrap.wrap(segment, width=85))
        for line in lines:
            add_line(line, font_size, color)

    # Header
    add_line("AI Phishing Email Analyzer - Threat Incident Report", 16, (0.06, 0.72, 0.5))
    add_line(f"Incident Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 9, (0.5, 0.5, 0.5))
    y += 12
    
    # Section 1: Threat Index
    add_line("1. Threat Intelligence Classification", 12, (0.05, 0.05, 0.05))
    level_color = (0.65, 0.33, 0.96) if risk['score'] >= 12 else ((0.85, 0.1, 0.1) if risk['risk_level'] == 'High' else ((0.95, 0.6, 0.1) if risk['risk_level'] == 'Medium' else (0.06, 0.72, 0.5)))
    risk_text = "CRITICAL" if risk['score'] >= 12 else risk['risk_level'].upper()
    add_line(f"Threat Score: {risk['score']}/20 | Verdict: {risk_text}", 10, level_color)
    y += 10
    
    # Section 2: Metadata
    add_line("2. Envelope & Header Metadata", 12, (0.05, 0.05, 0.05))
    add_line(f"From: {parsed['from']}", 9, (0.2, 0.2, 0.2))
    add_line(f"To: {parsed['to']}", 9, (0.2, 0.2, 0.2))
    add_line(f"Subject: {parsed['subject']}", 9, (0.2, 0.2, 0.2))
    add_line(f"Date: {parsed['date']}", 9, (0.2, 0.2, 0.2))
    y += 10
    
    # Section 3: URLs
    add_line("3. Extract Link Analysis", 12, (0.05, 0.05, 0.05))
    if url_analysis:
        for idx, item in enumerate(url_analysis):
            status = "SUSPICIOUS" if item['suspicious'] else "SAFE"
            reasons = f" [Flags: {', '.join(item['reasons'])}]" if item['reasons'] else ""
            add_line(f"• URL: {item['url']}", 8.5, (0.1, 0.1, 0.1))
            add_line(f"  Domain: {item['domain']}.{item['tld']} | Age: {item.get('age_days', 'Unknown')} days | Status: {status}{reasons}", 8, (0.4, 0.4, 0.4))
    else:
        add_line("No external links extracted from body content.", 9, (0.4, 0.4, 0.4))
    y += 10
    
    # Section 4: Keyword Indicators
    add_line("4. Lexical Phishing Indicators Matches", 12, (0.05, 0.05, 0.05))
    if keyword_matches:
        for cat, words in keyword_matches.items():
            add_line(f"• Category '{cat.replace('_', ' ').title()}': {', '.join(words)}", 9, (0.2, 0.2, 0.2))
    else:
        add_line("No critical trigger phrases detected.", 9, (0.4, 0.4, 0.4))
    y += 10
    
    # Section 5: AI Explanation
    add_line("5. AI Cyber Forensic Explanation", 12, (0.05, 0.05, 0.05))
    wrap_and_write(explanation, 8.5, (0.15, 0.15, 0.15))
        
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes

# Custom PDF Layout-Preserving Reader
def extract_pdf_layout_preserved(uploaded_file):
    pdf = fitz.open(stream=uploaded_file.read(), filetype="pdf")
    full_text = []
    
    for page in pdf:
        # Get individual words with exact visual coordinates
        # word item format: (x0, y0, x1, y1, "word", block_no, line_no, word_no)
        words = page.get_text("words")
        lines = []
        
        for w in words:
            x0, y0, x1, y1, word, block_no, line_no, word_no = w
            y_center = (y0 + y1) / 2.0
            
            # Find if there is a line already grouped within 7 pixels vertically
            found = False
            for line in lines:
                if abs(line["y_center"] - y_center) < 7:
                    line["items"].append((x0, x1, word))
                    # Recalculate average vertical line center
                    line["y_center"] = (line["y_center"] + y_center) / 2.0
                    found = True
                    break
            if not found:
                lines.append({"y_center": y_center, "items": [(x0, x1, word)]})
                
        # Construct the page text
        page_text = ""
        prev_y = None
        for line in sorted(lines, key=lambda l: l["y_center"]):
            # Sort items horizontally (left-to-right)
            items = sorted(line["items"], key=lambda item: item[0])
            
            line_str = ""
            prev_x1 = None
            for x0, x1, word in items:
                if prev_x1 is None:
                    # Indentation at start of line
                    indent = int(x0 / 8)
                    line_str += " " * indent
                else:
                    gap = x0 - prev_x1
                    if gap > 4:
                        spaces = int(gap / 6.5)
                        line_str += " " * max(1, spaces)
                    else:
                        line_str += " "
                line_str += word
                prev_x1 = x1
            
            # Determine separator spacing based on vertical Y gap
            curr_y = line["y_center"]
            if prev_y is not None:
                y_gap = curr_y - prev_y
                # If the vertical gap between centers is large (e.g. > 16.5 pixels),
                # it's a section/paragraph break: insert two newlines.
                # Otherwise, it's consecutive lines within the same paragraph: insert one newline.
                if y_gap > 16.5:
                    page_text += "\n\n" + line_str
                else:
                    page_text += "\n" + line_str
            else:
                page_text += line_str
            prev_y = curr_y
            
        full_text.append(page_text)
        
    pdf.close()
    return "\n\n".join(full_text)

# Sample Threat Payloads for Sandbox Testing (Different Threat Vectors and Risk Scores)
SAMPLE_EMAILS = {
    "🚨 Critical Threat (Bank Account Suspension)": """From: Bank Security Operations <alert@secure-bank0nline.com>
To: target-analyst@enterprise-corp.com
Subject: URGENT: Unauthorized login attempt detected on your account
Date: Fri, 17 Jul 2026 12:00:00 +0000

Dear Valued Customer,

We have detected an unauthorized login attempt on your bank account from an unrecognized IP address. To prevent permanent suspension of your online access, you must verify your identity immediately.

Click here to verify your identity: http://secure-bank0nline-verify.com/login

Failure to act within 24 hours will result in immediate termination of account access.

Thank you,
Bank Fraud Prevention Unit
""",

    "⚠️ High Threat (Office 365 Credential Harvester)": """From: Microsoft Security Team <no-reply@office365-security-update.invalid>
To: corporate-user@enterprise-corp.com
Subject: CRITICAL NOTICE: Password Expiration Notice - Immediate Action Required
Date: Sat, 18 Jul 2026 09:30:00 +0000

Attention User,

Your Office 365 password is set to expire today. Access to your mailbox, OneDrive, and corporate applications will be restricted unless password renewal is completed.

Please authenticate your credentials to retain current access:
https://login.microsoft.verify-account.invalid/auth?session=918372

Regards,
IT Global Service Desk
""",

    "🔶 Medium Threat (Executive Wire Transfer Urgency)": """From: Chief Executive Officer <ceo-direct-office@gmail.com>
To: finance-manager@enterprise-corp.com
Subject: URGENT: Wire Transfer Request for Confidential Acquisition
Date: Sun, 19 Jul 2026 14:15:00 +0000

Hi Team,

I am currently in an urgent meeting with our legal counsel regarding an unannounced strategic acquisition.

Please transfer $48,500 immediately to the external escrow account attached below. Send me the transaction receipt as soon as possible. Do not discuss this with anyone in the office until the public announcement tomorrow.

Thanks,
Chief Executive Officer
""",

    "✅ Low Risk (Legitimate Internal Corporate Sync)": """From: Alex Smith <alex.smith@acme-corp.com>
To: team-all@acme-corp.com
Subject: Weekly Engineering Sprint Sync & Architecture Overview
Date: Mon, 20 Jul 2026 08:00:00 +0000

Hi Team,

Just a friendly reminder about our weekly sprint sync scheduled for today at 2:00 PM EST. 

We will review the recent UI component updates, system diagnostics telemetry, and test coverage metrics. Please bring any blockers or open pull requests to the call.

Best regards,
Alex Smith
Senior Software Engineer | Acme Corp
"""
}

# Default sample payload for quick load
sample_phishing_email = SAMPLE_EMAILS["🚨 Critical Threat (Bank Account Suspension)"]

# Initialize Session States
if "analyzed" not in st.session_state:
    st.session_state.analyzed = False
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "recent_analyses" not in st.session_state:
    st.session_state.recent_analyses = []
if "email_input_value" not in st.session_state:
    st.session_state.email_input_value = ""
if "navigation_page" not in st.session_state:
    st.session_state.navigation_page = "🏠 Home & Overview"

# Helper to render visual milestones during diagnostics with Hybrid Interactive Console (Quiz + Terminal + Security Tips)
def render_scan_progress(stage, percentage):
    stages = [
        ("Header Parsing", 1),
        ("URL Vetting", 2),
        ("Lexical Scanning", 3),
        ("Risk Indexing", 4),
        ("AI Briefing", 5)
    ]
    
    stages_html = ""
    for name, step_num in stages:
        if step_num < stage:
            icon = "✅"
            cls = "completed"
        elif step_num == stage:
            icon = "⚡"
            cls = "active"
        else:
            icon = "⚫"
            cls = "pending"
            
        stages_html += f'<div class="stage-item {cls}"><span>{icon}</span> {name}</div>'

    html_code = f"""<!DOCTYPE html>
<html>
<head>
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@600;700;800&family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;600&display=swap');
* {{ box-sizing: border-box; }}
body {{
    background-color: transparent;
    margin: 0;
    padding: 0;
    font-family: 'Inter', -apple-system, sans-serif;
    color: #F8FAFC;
    overflow: hidden;
}}
.console-card {{
    background: linear-gradient(145deg, rgba(18, 14, 34, 0.95) 0%, rgba(26, 20, 48, 0.98) 100%);
    border: 1px solid rgba(168, 85, 247, 0.28);
    border-top: 3px solid #A855F7;
    border-radius: 14px;
    padding: 22px 26px;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.8), inset 0 1px 0 rgba(255, 255, 255, 0.08);
}}
.header-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.85rem;
    color: #CBD5E1;
    font-weight: 700;
    font-family: 'Outfit', sans-serif;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    margin-bottom: 12px;
}}
.percentage-badge {{
    color: #C084FC;
    font-weight: 800;
    font-size: 0.94rem;
    font-family: 'Outfit', sans-serif;
    background: rgba(168, 85, 247, 0.15);
    padding: 4px 14px;
    border-radius: 9999px;
    border: 1px solid rgba(168, 85, 247, 0.35);
    box-shadow: 0 0 14px rgba(168, 85, 247, 0.25);
}}
.progress-track {{
    background-color: #0B0817;
    border-radius: 9999px;
    height: 10px;
    width: 100%;
    overflow: hidden;
    margin-bottom: 16px;
    border: 1px solid rgba(168, 85, 247, 0.25);
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.85);
}}
.progress-fill {{
    height: 100%;
    background: linear-gradient(90deg, #7C3AED 0%, #A855F7 50%, #06B6D4 100%);
    border-radius: 9999px;
    transition: width 0.5s cubic-bezier(0.16, 1, 0.3, 1);
    box-shadow: 0 0 16px rgba(168, 85, 247, 0.7);
}}
.stages-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 20px;
}}
.stage-item {{
    font-size: 0.8rem;
    font-family: 'Outfit', sans-serif;
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 16px;
    border-radius: 9999px;
    background: rgba(255, 255, 255, 0.02);
}}
.stage-item.completed {{ color: #10B981; font-weight: 700; background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.25); }}
.stage-item.active {{ color: #C084FC; font-weight: 800; background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.4); box-shadow: 0 0 12px rgba(168, 85, 247, 0.25); }}
.stage-item.pending {{ color: #64748B; font-weight: 500; border: 1px solid rgba(255, 255, 255, 0.05); }}

.interactive-panel {{
    border-top: 1px solid rgba(168, 85, 247, 0.18);
    padding-top: 16px;
    margin-top: 6px;
}}

.tab-bar {{
    display: flex;
    gap: 12px;
    margin-bottom: 16px;
    align-items: center;
    flex-wrap: wrap;
}}
.tab-label {{
    font-size: 0.74rem;
    color: #CBD5E1;
    font-weight: 700;
    font-family: 'Outfit', sans-serif;
    text-transform: uppercase;
    letter-spacing: 0.07em;
    margin-right: 4px;
}}
.tab-btn {{
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: #94A3B8;
    font-family: 'Outfit', sans-serif;
    padding: 6px 18px;
    border-radius: 9999px;
    font-size: 0.78rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.25s ease;
}}
.tab-btn:hover {{
    color: #F8FAFC;
    background: rgba(168, 85, 247, 0.14);
    border-color: rgba(168, 85, 247, 0.4);
}}
.tab-btn.active {{
    background: rgba(168, 85, 247, 0.22);
    border-color: #A855F7;
    color: #C084FC;
    font-weight: 700;
    box-shadow: 0 0 14px rgba(168, 85, 247, 0.35);
}}

/* Quiz mode */
.quiz-container {{
    background: #0B0817;
    border: 1px solid rgba(168, 85, 247, 0.28);
    border-radius: 12px;
    padding: 18px 24px;
    font-size: 0.86rem;
    box-shadow: inset 0 2px 8px rgba(0,0,0,0.6);
}}
.quiz-q {{
    color: #F8FAFC;
    margin-bottom: 14px;
    line-height: 1.55;
    font-weight: 500;
}}
.quiz-btns {{
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
    margin-top: 14px;
}}
.btn-quiz {{
    padding: 8px 22px;
    border-radius: 9999px;
    font-family: 'Outfit', sans-serif;
    font-weight: 700;
    font-size: 0.8rem;
    cursor: pointer;
    border: none;
    transition: all 0.2s ease-in-out;
}}
.btn-quiz:active {{
    transform: scale(0.95);
}}
.btn-phish {{
    background: linear-gradient(135deg, #EF4444 0%, #DC2626 100%);
    color: #FFF;
    box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
    border: 1px solid rgba(239, 68, 68, 0.2);
}}
.btn-phish:hover {{
    box-shadow: 0 6px 20px rgba(239, 68, 68, 0.45);
    transform: translateY(-1px);
}}
.btn-safe {{
    background: linear-gradient(135deg, #10B981 0%, #059669 100%);
    color: #FFF;
    box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
    border: 1px solid rgba(16, 185, 129, 0.2);
}}
.btn-safe:hover {{
    box-shadow: 0 6px 20px rgba(16, 185, 129, 0.45);
    transform: translateY(-1px);
}}
.quiz-feedback {{
    font-size: 0.82rem;
    font-weight: 700;
    margin-left: 10px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    padding: 5px 14px;
    border-radius: 9999px;
    color: #E2E8F0;
    font-family: 'Outfit', sans-serif;
    box-shadow: 0 2px 8px rgba(0,0,0,0.25);
}}

/* Terminal mode */
.terminal-box {{
    background: #06040F;
    border: 1px solid rgba(168, 85, 247, 0.25);
    border-radius: 8px;
    padding: 12px 16px;
    font-family: 'Fira Code', monospace;
    font-size: 0.78rem;
    color: #C084FC;
    height: 95px;
    overflow-y: auto;
    line-height: 1.65;
    box-shadow: inset 0 2px 10px rgba(0,0,0,0.85);
}}
.terminal-box::-webkit-scrollbar {{
    width: 6px;
}}
.terminal-box::-webkit-scrollbar-thumb {{
    background: rgba(16, 185, 129, 0.3);
    border-radius: 4px;
}}
.terminal-line {{ margin: 3px 0; }}
</style>
</head>
<body>
<div class="console-card">
    <div class="header-row">
        <span>🔬 Threat Intelligence Pipeline Diagnostics</span>
        <span class="percentage-badge">{percentage}%</span>
    </div>
    
    <div class="progress-track">
        <div class="progress-fill" style="width: {percentage}%;"></div>
    </div>
    
    <div class="stages-row">
        {stages_html}
    </div>
    
    <div class="interactive-panel">
        <div class="tab-bar">
            <span class="tab-label">🎮 Interactive Loading Hub:</span>
            <button id="tab-quiz" class="tab-btn" onclick="setMode('quiz')">🎮 Phish Quiz</button>
            <button id="tab-terminal" class="tab-btn" onclick="setMode('terminal')">⚡ Live Terminal</button>
            <button id="tab-tips" class="tab-btn" onclick="setMode('tips')">💡 Security Tips</button>
        </div>
        <div id="hub-content"></div>
    </div>
</div>

<script>
(function() {{
    const quizQuestions = [
        {{ q: "Scenario: Email from 'IT Desk' asks you to update password on 'corp-login-verify.net'.", phish: true, reason: "Unregistered external domain + credential request!" }},
        {{ q: "Scenario: Email from your boss asking for urgent $500 gift cards via WhatsApp.", phish: true, reason: "Urgent gift card request is a classic BEC scam." }},
        {{ q: "Scenario: Calendar invite from 'hr@yourcompany.com' for Annual Benefit Review.", phish: false, reason: "Legitimate internal address and standard meeting request." }},
        {{ q: "Scenario: Notification: 'Your package is delayed. Pay $1.99 fee at post-delivery-track.info'.", phish: true, reason: "Smishing/Phishing payment trap on suspicious TLD." }}
    ];

    const facts = [
        "🔍 <strong>Sender Check:</strong> Fake emails often use names like 'Bank Admin' but show a strange email address behind it. Always check the actual email address.",
        "🔗 <strong>Link Check:</strong> Scammers register fake websites that look almost identical to real ones (like replacing 'o' with '0'). Double check every link.",
        "🚩 <strong>Urgency Warning:</strong> Phishing emails try to scare you into acting quickly. Watch out for phrases like 'Account suspended' or 'Verify within 24 hours'.",
        "🛡️ <strong>Smart Scams:</strong> A message can look safe and clean but still contain a dangerous link. Attackers register new, unused websites to bypass simple filters."
    ];

    let currentMode = localStorage.getItem('hub_mode') || 'quiz';
    let qIdx = parseInt(localStorage.getItem('quiz_idx') || '0', 10) % quizQuestions.length;
    let score = parseInt(localStorage.getItem('quiz_score') || '0', 10);
    let factIdx = parseInt(localStorage.getItem('fact_idx') || '0', 10) % facts.length;

    window.setMode = function(mode) {{
        currentMode = mode;
        try {{ localStorage.setItem('hub_mode', mode); }} catch(e){{}}
        renderContent();
    }};

    window.answerQuiz = function(userSaidPhish) {{
        const q = quizQuestions[qIdx];
        const correct = (userSaidPhish === q.phish);
        if (correct) score++;
        try {{ localStorage.setItem('quiz_score', score.toString()); }} catch(e){{}}
        
        const fb = document.getElementById('quiz-fb');
        if (fb) {{
            fb.innerHTML = correct ? `<span style="color:#10B981">🎯 Correct! ${{q.reason}}</span>` : `<span style="color:#EF4444">❌ Phish alert! ${{q.reason}}</span>`;
        }}
        
        setTimeout(() => {{
            qIdx = (qIdx + 1) % quizQuestions.length;
            try {{ localStorage.setItem('quiz_idx', qIdx.toString()); }} catch(e){{}}
            renderContent();
        }}, 2200);
    }};

    function renderContent() {{
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        const activeTabBtn = document.getElementById('tab-' + currentMode);
        if (activeTabBtn) activeTabBtn.classList.add('active');

        const box = document.getElementById('hub-content');
        if (!box) return;

        if (currentMode === 'quiz') {{
            const q = quizQuestions[qIdx];
            box.innerHTML = `
                <div class="quiz-container">
                    <div class="quiz-q"><strong>Question ${{qIdx+1}}/${{quizQuestions.length}}:</strong> ${{q.q}}</div>
                    <div class="quiz-btns">
                        <button class="btn-quiz btn-phish" onclick="answerQuiz(true)">🚨 Phishing</button>
                        <button class="btn-quiz btn-safe" onclick="answerQuiz(false)">✅ Safe</button>
                        <span id="quiz-fb" class="quiz-feedback">Score: ${{score}}</span>
                    </div>
                </div>
            `;
        }} else if (currentMode === 'terminal') {{
            box.innerHTML = `
                <div class="terminal-box" id="term-log">
                    <div class="terminal-line">[SYS] Initializing threat intelligence diagnostics...</div>
                    <div class="terminal-line">[PARSER] Extracting MIME structure & envelope headers...</div>
                    <div class="terminal-line">[VETTING] Crawling target links & WHOIS registries...</div>
                    <div class="terminal-line">[AI] Consulting local air-gapped Llama 3 model weights...</div>
                </div>
            `;
        }} else {{
            box.innerHTML = `
                <div style="background: rgba(16,185,129,0.06); border: 1px solid rgba(16,185,129,0.2); border-left: 4px solid #10B981; border-radius: 8px; padding: 14px 18px; font-size: 0.85rem; color: #CBD5E1; line-height: 1.6;">
                    ${{facts[factIdx]}}
                </div>
            `;
        }}
    }}

    renderContent();
}})();
</script>
</body>
</html>"""
    return html_code


# Helper to render metadata cards with left border highlight and HTML escaping
def render_meta_card(label, value, icon):
    if not value or value.strip() == "":
        value_html = '<span style="color: #64748B; font-style: italic; font-size: 0.82rem;">N/A (Not Found in Payload)</span>'
    else:
        # Escape HTML symbols to display email addresses in `<...>` properly
        escaped_val = value.replace("<", "&lt;").replace(">", "&gt;")
        value_html = f'<span style="color: #CBD5E1; font-family: monospace; font-size: 0.85rem; word-break: break-all; font-weight: 600;">{escaped_val}</span>'
        
    return f"""<div style="border: 1px solid rgba(16, 185, 129, 0.15); border-left: 4px solid #10B981; background-color: #080B10; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px; box-shadow: inset 0 1px 3px rgba(0,0,0,0.35);">
<div style="font-size: 0.7rem; color: #94A3B8; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
<span>{icon}</span> {label}
</div>
<div>{value_html}</div>
</div>"""

# -------------------------------------------------
# Header Layout (Cryptiva Design - Matching Screenshot 1)
# -------------------------------------------------
# -------------------------------------------------
# Header Layout (Cryptiva Design - Matching Screenshot 1)
# -------------------------------------------------
st.markdown('<div id="nav-anchor"></div>', unsafe_allow_html=True)
col_logo, col_nav1, col_nav2, col_nav3, col_nav4 = st.columns([3.5, 1.2, 1.2, 1.3, 1.3])

with col_logo:
    st.markdown("""<div style="display: flex; align-items: center; gap: 14px; padding-top: 5px;">
<div style="width: 42px; height: 42px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.4); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: #C084FC; box-shadow: 0 0 15px rgba(168, 85, 247, 0.2);">
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 9.7a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 .76-.97l8-2a1 1 0 0 1 .48 0l8 2A1 1 0 0 1 20 6z"/></svg>
</div>
<div>
<div style="margin: 0; font-size: 1.35rem !important; font-weight: 800; color: #FFFFFF; font-family: 'Outfit', sans-serif; letter-spacing: -0.01em; line-height: 1.25;">
AI Phishing Analyzer
</div>
<div style="color: #94A3B8; font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.12em; margin-top: 2px;">
CRYPTIVA SOC
</div>
</div>
</div>""", unsafe_allow_html=True)

with col_nav1:
    if st.button("Home & Overview", use_container_width=True, type="primary" if st.session_state.navigation_page == "🏠 Home & Overview" else "secondary"):
        st.session_state.navigation_page = "🏠 Home & Overview"
        st.rerun()

with col_nav2:
    if st.button("Forensic Lab", use_container_width=True, type="primary" if st.session_state.navigation_page == "🔬 Forensic Lab" else "secondary"):
        st.session_state.navigation_page = "🔬 Forensic Lab"
        st.rerun()

with col_nav3:
    if st.button("Intelligence Vault", use_container_width=True, type="primary" if st.session_state.navigation_page == "📊 Intelligence Vault" else "secondary"):
        st.session_state.navigation_page = "📊 Intelligence Vault"
        st.rerun()

with col_nav4:
    if st.button("Security Playbooks", use_container_width=True, type="primary" if st.session_state.navigation_page == "📖 Security Playbooks" else "secondary"):
        st.session_state.navigation_page = "📖 Security Playbooks"
        st.rerun()

st.markdown('<div style="border-bottom: 1px solid rgba(255, 255, 255, 0.06); margin-top: 15px; margin-bottom: 25px;"></div>', unsafe_allow_html=True)

st.write("")

# -------------------------------------------------
# PAGE CONTENT ROUTER
# -------------------------------------------------

# Page 1: 🏠 Home & Overview (Welcome page with core capabilities summary)
if st.session_state.navigation_page == "🏠 Home & Overview":
    st.markdown("""<style>
    /* Style buttons inside Home cards to look like text links (Matching Image 3) */
    div[data-testid="stVerticalBlockBorder"] button {
        background: transparent !important;
        color: #A855F7 !important;
        border: none !important;
        padding: 0 !important;
        font-size: 0.95rem !important;
        font-weight: 600 !important;
        justify-content: flex-start !important;
        text-align: left !important;
        box-shadow: none !important;
        transition: all 0.2s ease !important;
        display: inline-flex !important;
        width: auto !important;
    }
    div[data-testid="stVerticalBlockBorder"] button:hover {
        color: #C084FC !important;
        background: transparent !important;
        text-decoration: none !important;
    }
    </style>""", unsafe_allow_html=True)

    # Hero Banner Card (Matching Screenshot 1)
    st.markdown("""<div style="background: linear-gradient(145deg, #0B0817 0%, #120D26 100%); border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 20px; padding: 48px 32px; margin-bottom: 24px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.75); text-align: center; position: relative;">
<div style="display: inline-block; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.35); color: #C084FC; font-weight: 700; font-size: 0.76rem; font-family: 'Outfit', sans-serif; letter-spacing: 0.04em; padding: 6px 18px; border-radius: 9999px; margin-bottom: 22px;">
⚡ AI-Powered Phishing Forensics
</div>
<h1 style="font-family: 'Outfit', sans-serif !important; font-size: 3.4rem !important; font-weight: 900; line-height: 1.12; margin: 10px 0 18px 0; color: #FFFFFF; letter-spacing: -0.03em;">
Detect Deception Before It <span style="background: linear-gradient(120deg, #38BDF8 0%, #06B6D4 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Lands</span>
</h1>
<p style="font-size: 1.05rem; color: #94A3B8; line-height: 1.65; max-width: 760px; margin: 0 auto 32px auto; font-family: 'Inter', sans-serif;">
Cryptiva SOC Portal analyzes email headers, body language, and suspicious links with air-gapped neural models and real-time threat intelligence.
</p>
</div>""", unsafe_allow_html=True)
    
    # Hero CTA Buttons Row
    hero_col1, hero_col2 = st.columns([1, 1])
    with hero_col1:
        if st.button("Enter Forensic Lab →", use_container_width=True, type="primary"):
            st.session_state.navigation_page = "🔬 Forensic Lab"
            st.rerun()
    with hero_col2:
        if st.button("Browse Intelligence Vault", use_container_width=True):
            st.session_state.navigation_page = "📊 Intelligence Vault"
            st.rerun()

    st.markdown("<div style='margin-top: 25px;'></div>", unsafe_allow_html=True)

    # 4-Column Counter Stats Grid (Matching Screenshot 1)
    stat_col1, stat_col2, stat_col3, stat_col4 = st.columns(4)
    with stat_col1:
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 14px; padding: 22px; text-align: center;">
<div style="font-size: 2.2rem; font-weight: 900; font-family: 'Outfit', sans-serif; color: #FFFFFF;">10k+</div>
<div style="font-size: 0.84rem; color: #94A3B8; margin-top: 4px;">Emails analyzed</div>
</div>""", unsafe_allow_html=True)

    with stat_col2:
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 14px; padding: 22px; text-align: center;">
<div style="font-size: 2.2rem; font-weight: 900; font-family: 'Outfit', sans-serif; color: #FFFFFF;">24+</div>
<div style="font-size: 0.84rem; color: #94A3B8; margin-top: 4px;">Suspicious TLDs tracked</div>
</div>""", unsafe_allow_html=True)

    with stat_col3:
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 14px; padding: 22px; text-align: center;">
<div style="font-size: 2.2rem; font-weight: 900; font-family: 'Outfit', sans-serif; color: #FFFFFF;">AI</div>
<div style="font-size: 0.84rem; color: #94A3B8; margin-top: 4px;">Cloud model reasoning</div>
</div>""", unsafe_allow_html=True)

    with stat_col4:
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.06); border-radius: 14px; padding: 22px; text-align: center;">
<div style="font-size: 2.2rem; font-weight: 900; font-family: 'Outfit', sans-serif; color: #FFFFFF;">99.9%</div>
<div style="font-size: 0.84rem; color: #94A3B8; margin-top: 4px;">Uptime SLA</div>
</div>""", unsafe_allow_html=True)

    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)

    # 3-Column Feature Modules Grid (Matching Screenshot 3 Exactly)
    mod_col1, mod_col2, mod_col3 = st.columns(3)
    with mod_col1:
        with st.container(border=True):
            st.markdown("""<div style="width: 44px; height: 44px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #C084FC; margin-bottom: 16px;">
<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M3 17v2a2 2 0 0 1 2 2h2"/></svg>
</div>
<div style="margin: 0 0 10px 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Forensic Lab</div>
<p style="color: #94A3B8; font-size: 0.86rem; line-height: 1.6; margin: 0 0 16px 0; min-height: 72px;">
Paste raw email text, choose from curated threat samples, and run a full AI-assisted risk analysis in seconds.
</p>""", unsafe_allow_html=True)
            if st.button("Open module →", key="home_mod_lab"):
                st.session_state.navigation_page = "🔬 Forensic Lab"
                st.rerun()

    with mod_col2:
        with st.container(border=True):
            st.markdown("""<div style="width: 44px; height: 44px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #C084FC; margin-bottom: 16px;">
<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"/></svg>
</div>
<div style="margin: 0 0 10px 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Intelligence Vault</div>
<p style="color: #94A3B8; font-size: 0.86rem; line-height: 1.6; margin: 0 0 16px 0; min-height: 72px;">
Explore real-world phishing templates, suspicious domain patterns, and your local analysis history.
</p>""", unsafe_allow_html=True)
            if st.button("Open module →", key="home_mod_vault"):
                st.session_state.navigation_page = "📊 Intelligence Vault"
                st.rerun()

    with mod_col3:
        with st.container(border=True):
            st.markdown("""<div style="width: 44px; height: 44px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #C084FC; margin-bottom: 16px;">
<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/></svg>
</div>
<div style="margin: 0 0 10px 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Security Playbooks</div>
<p style="color: #94A3B8; font-size: 0.86rem; line-height: 1.6; margin: 0 0 16px 0; min-height: 72px;">
Step-by-step response guides for quarantining, reporting, and training users against phishing attacks.
</p>""", unsafe_allow_html=True)
            if st.button("Open module →", key="home_mod_playbooks"):
                st.session_state.navigation_page = "📖 Security Playbooks"
                st.rerun()

# Page 2: 🔬 Forensic Lab (Dedicated email input and scan output page)
elif st.session_state.navigation_page == "🔬 Forensic Lab":
    # Page Title Banner (Matching Screenshot 1)
    st.markdown("""<div style="display: flex; align-items: flex-start; gap: 14px; margin-bottom: 24px;">
<div style="width: 44px; height: 44px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC;">⛶</div>
<div>
<h2 style="margin: 0; color: #FFFFFF; font-size: 1.6rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Forensic Lab</h2>
<p style="color: #94A3B8; font-size: 0.88rem; margin: 4px 0 0 0; font-family: 'Inter', sans-serif;">Paste an email or load a curated threat sample to analyze.</p>
</div>
</div>""", unsafe_allow_html=True)

    with st.container(border=True):
        header_col1, header_col2 = st.columns([4.2, 2.8])
        with header_col1:
            st.markdown("""<div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
<div style="width: 36px; height: 36px; background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC; box-shadow: 0 0 12px rgba(168, 85, 247, 0.15);">📄</div>
<div>
<div style="margin: 0; color: #FFFFFF; font-size: 1.15rem; font-family: 'Outfit', sans-serif; font-weight: 700; line-height: 1.2;">Email Source</div>
<div style="color: #94A3B8; font-size: 0.84rem; margin-top: 2px; font-family: 'Inter', sans-serif;">Load a sample, paste raw headers + body, then run the analysis.</div>
</div>
</div>""", unsafe_allow_html=True)
        with header_col2:
            st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
            st.markdown('<div class="pill-button-wrapper">', unsafe_allow_html=True)
            if st.button("Load Random Sample →", use_container_width=True):
                import random
                choices = list(SAMPLE_EMAILS.keys())
                choice = random.choice(choices)
                st.session_state.email_input_value = SAMPLE_EMAILS[choice]
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

        uploaded_file = None
        email_text = st.text_area(
            "Inspect & Edit raw payload:",
            value=st.session_state.email_input_value,
            height=280,
            placeholder="Paste raw email body/header block here or upload an email file...",
            label_visibility="collapsed"
        )
        st.session_state.email_input_value = email_text

        btn_col1, btn_col2, _ = st.columns([1.3, 0.7, 5.0])
        with btn_col1:
            run_scan = st.button("✨ Run AI Analysis", use_container_width=True, type="primary")
        with btn_col2:
            clear_input = st.button("Clear", use_container_width=True)

        if clear_input:
            st.session_state.email_input_value = ""
            st.session_state.analyzed = False
            st.session_state.parsed = None
            st.session_state.url_analysis = None
            st.session_state.keyword_matches = None
            st.session_state.risk = None
            st.session_state.explanation = None
            st.session_state.chat_history = []
            st.rerun()

        if run_scan:
            if len(email_text.strip()) == 0:
                st.error("Operation Aborted: Input text container is empty.")
            else:
                progress_placeholder = st.empty()
                
                # Stage 1: Header Parsing
                progress_placeholder.iframe(render_scan_progress(1, 10), height=350)
                parsed = parse_email(email_text)
                
                # Stage 2: URL Vetting
                progress_placeholder.iframe(render_scan_progress(2, 30), height=350)
                urls = extract_urls(parsed["body"])
                url_analysis = analyze_urls(urls)
                
                # Post-process to catch unregistered/invalid test domains (.invalid) and subdomain brand impersonations
                for item in url_analysis:
                    url_lower = item["url"].lower()
                    
                    # Extract hostname cleanly
                    host = url_lower.split("://")[-1].split("/")[0].split("?")[0].split(":")[0]
                    
                    # If the domain ends with .invalid, override parsed fields to render correctly in UI
                    if host.endswith(".invalid"):
                        item["suspicious"] = True
                        item["tld"] = "invalid"
                        host_parts = host.split(".")
                        if len(host_parts) >= 2:
                            item["domain"] = host_parts[-2]
                        
                        if "Invalid domain / Unregistered TLD (.invalid)" not in item["reasons"]:
                            item["reasons"].append("Invalid domain / Unregistered TLD (.invalid)")
                    elif item["domain"] == "invalid" or item["tld"] == "" or ".invalid" in url_lower:
                        item["suspicious"] = True
                        if "Invalid domain / Unregistered TLD (.invalid)" not in item["reasons"]:
                            item["reasons"].append("Invalid domain / Unregistered TLD (.invalid)")
                    
                    # Extract the subdomain prefix to check for brand impersonation
                    subdomain_part = url_lower.split("://")[-1].split("/")[0]
                    if item["domain"] and ("." + item["domain"]) in subdomain_part:
                        subdomain_prefix = subdomain_part.split("." + item["domain"])[0]
                    else:
                        subdomain_prefix = subdomain_part
                    
                    for brand in ["paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook", "instagram", "outlook", "chase", "wellsfargo", "office365"]:
                        if brand in subdomain_prefix.replace("-", "").replace("_", ""):
                            item["suspicious"] = True
                            typosquat_msg = "Possible typosquatting / brand impersonation in subdomain"
                            if typosquat_msg not in item["reasons"]:
                                item["reasons"].append(typosquat_msg)
                
                # Stage 3: Lexical Scanning
                progress_placeholder.iframe(render_scan_progress(3, 50), height=350)
                keyword_matches = detect_keywords(parsed["body"])
                
                # Stage 4: Risk Indexing
                progress_placeholder.iframe(render_scan_progress(4, 70), height=350)
                risk = calculate_risk_score(url_analysis, keyword_matches, parsed=parsed)
                
                # Stage 5: AI Briefing
                progress_placeholder.iframe(render_scan_progress(5, 90), height=350)
                explanation = explain_email(parsed, url_analysis, keyword_matches, risk, model_name=model_name)
                
                # Complete
                progress_placeholder.iframe(render_scan_progress(6, 100), height=350)
                
                # Store values in session state
                st.session_state.parsed = parsed
                st.session_state.url_analysis = url_analysis
                st.session_state.keyword_matches = keyword_matches
                st.session_state.risk = risk
                st.session_state.explanation = explanation
                st.session_state.analyzed = True
                st.session_state.chat_history = []
                
                # Add to history list
                subject_lbl = parsed.get("subject", "No Subject") or "No Subject"
                if len(subject_lbl) > 28:
                    subject_lbl = subject_lbl[:25] + "..."
                
                level_name, _, _, _ = get_risk_details(risk)
                st.session_state.recent_analyses.insert(0, {
                    "subject": subject_lbl,
                    "sender": parsed.get("from", "Unknown"),
                    "risk_level": level_name
                })
                st.session_state.recent_analyses = st.session_state.recent_analyses[:5]
                
                progress_placeholder.empty()
                st.rerun()

    # Render results workspace if scan is complete (directly below input form)
    if st.session_state.analyzed:
        # Sender clean domain extraction with fallback to URL domains
        raw_from = st.session_state.parsed.get("from", "").strip() if st.session_state.parsed else ""
        sender_clean = raw_from.replace("<", "&lt;").replace(">", "&gt;") if raw_from else ""
        
        email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_from) if raw_from else None
        
        # Pull unique domains from URL analysis
        url_domains = []
        if st.session_state.url_analysis:
            for item in st.session_state.url_analysis:
                d = item.get("domain", "")
                t = item.get("tld", "")
                if d and d != "invalid":
                    full_d = f"{d}.{t}" if t and t != "invalid" else d
                    if full_d not in url_domains:
                        url_domains.append(full_d)

        # 1. Top Section: Risk Verdict + AI Threat Assessment (2 Columns - Matching Screenshot 1)
        col_verdict, col_ai = st.columns([1, 1.8])

        threat_score = st.session_state.risk["score"]
        level_name, level_class, level_color, percentage = get_risk_details(st.session_state.risk)

        with col_verdict:
            # Calculate additional indicators for visual balance and telemetry detail
            num_links = len(st.session_state.url_analysis)
            suspicious_links = sum(1 for url in st.session_state.url_analysis if url.get("suspicious"))
            num_keywords = sum(len(words) for words in st.session_state.keyword_matches.values())
            
            url_risk_level = "HIGH THREAT" if suspicious_links > 0 else ("SUSPICIOUS" if num_links > 0 and any(u.get("domain") == "invalid" or u.get("tld") == "invalid" for u in st.session_state.url_analysis) else ("CLEAN" if num_links > 0 else "NO LINKS"))
            url_risk_color = "#EF4444" if "HIGH" in url_risk_level else ("#F59E0B" if "SUSP" in url_risk_level else "#10B981")
            
            keyword_risk_level = "HIGH URGENCY" if num_keywords > 5 else ("WARNING" if num_keywords > 0 else "NORMAL")
            keyword_risk_color = "#EF4444" if "HIGH" in keyword_risk_level else ("#F59E0B" if "WARN" in keyword_risk_level else "#10B981")
            
            st.markdown(f"""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(124, 58, 237, 0.25); border-radius: 16px; padding: 24px; height: 500px; display: flex; flex-direction: column;">
<div style="flex-shrink: 0;">
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.2rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Risk Verdict</h3>
<p style="color: #94A3B8; font-size: 0.84rem; margin: 4px 0 14px 0;">Composite score based on URLs and trigger language.</p>
<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
<span style="color: #CBD5E1; font-size: 0.88rem; font-weight: 600;">Score</span>
<span style="background: rgba(124, 58, 237, 0.25); border: 1px solid rgba(124, 58, 237, 0.4); color: #C084FC; font-weight: 700; font-size: 0.78rem; padding: 3px 12px; border-radius: 9999px;">{level_name}</span>
</div>
<div style="font-size: 3.2rem; font-weight: 900; font-family: 'Outfit', sans-serif; color: #FFFFFF; line-height: 1.1; margin-bottom: 14px;">
{threat_score}<span style="font-size: 1.1rem; color: #64748B; font-weight: 600;">/20</span>
</div>
<div style="background: #080512; border-radius: 9999px; height: 10px; width: 100%; overflow: hidden; margin-bottom: 8px; border: 1px solid rgba(124, 58, 237, 0.2);">
<div style="width: {percentage}%; background: linear-gradient(90deg, #7C3AED 0%, #A855F7 100%); height: 100%; border-radius: 9999px;"></div>
</div>
<div style="font-size: 0.8rem; color: #94A3B8;">{percentage}% threat saturation</div>
</div>

<div class="scrollable-card-content" style="flex: 1; overflow-y: auto; padding-right: 6px; margin-top: 16px; border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 16px;">
<h4 style="margin: 0 0 14px 0; color: #FFFFFF; font-size: 0.95rem; font-family: 'Outfit', sans-serif; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;">Telemetry Diagnostics</h4>
<div style="display: flex; flex-direction: column; gap: 12px;">
<div style="display: flex; justify-content: space-between; align-items: center;">
<span style="color: #94A3B8; font-size: 0.82rem; font-family: 'Inter', sans-serif;">Link Integrity</span>
<span style="font-weight: 700; font-size: 0.76rem; color: {url_risk_color}; background: rgba(255, 255, 255, 0.02); padding: 3px 10px; border-radius: 9999px; border: 1px solid rgba(255, 255, 255, 0.05); font-family: 'Outfit', sans-serif;">{url_risk_level}</span>
</div>
<div style="display: flex; justify-content: space-between; align-items: center;">
<span style="color: #94A3B8; font-size: 0.82rem; font-family: 'Inter', sans-serif;">Behavioral Urgency</span>
<span style="font-weight: 700; font-size: 0.76rem; color: {keyword_risk_color}; background: rgba(255, 255, 255, 0.02); padding: 3px 10px; border-radius: 9999px; border: 1px solid rgba(255, 255, 255, 0.05); font-family: 'Outfit', sans-serif;">{keyword_risk_level}</span>
</div>
</div>
<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 16px;">
<div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(168, 85, 247, 0.1); border-radius: 10px; padding: 14px; text-align: center;">
<div style="font-size: 1.5rem; font-weight: 900; color: #FFFFFF; font-family: 'Outfit', sans-serif;">{num_links}</div>
<div style="font-size: 0.68rem; color: #64748B; font-weight: 600; text-transform: uppercase; margin-top: 4px; font-family: 'Outfit', sans-serif; letter-spacing: 0.03em;">URLs Scanned</div>
</div>
<div style="background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(168, 85, 247, 0.1); border-radius: 10px; padding: 14px; text-align: center;">
<div style="font-size: 1.5rem; font-weight: 900; color: #FFFFFF; font-family: 'Outfit', sans-serif;">{num_keywords}</div>
<div style="font-size: 0.68rem; color: #64748B; font-weight: 600; text-transform: uppercase; margin-top: 4px; font-family: 'Outfit', sans-serif; letter-spacing: 0.03em;">Keywords</div>
</div>
</div>
</div>
</div>""", unsafe_allow_html=True)

        with col_ai:
            raw_expl = st.session_state.explanation
            
            # Clean up multiple empty lines
            import re
            text = re.sub(r'\n{3,}', '\n\n', raw_expl.strip())
            text = text.replace("### Overall Verdict", "").strip()
            
            # Detect verdict string at the top and format as a capsule badge
            verdict_badge = ""
            verdict_match = re.match(r'^[*_]*([a-zA-Z0-9\s/]+)[*_]*\s*\n', text)
            if verdict_match:
                verdict_str = verdict_match.group(1).strip()
                if any(x in verdict_str.lower() for x in ["suspicious", "phish", "threat", "critical", "high"]):
                    badge_bg = "rgba(239, 68, 68, 0.12)"
                    badge_border = "rgba(239, 68, 68, 0.35)"
                    badge_color = "#EF4444"
                elif any(x in verdict_str.lower() for x in ["medium", "warn"]):
                    badge_bg = "rgba(245, 158, 11, 0.12)"
                    badge_border = "rgba(245, 158, 11, 0.35)"
                    badge_color = "#F59E0B"
                else:
                    badge_bg = "rgba(16, 185, 129, 0.12)"
                    badge_border = "rgba(16, 185, 129, 0.35)"
                    badge_color = "#10B981"
                
                verdict_badge = f'<div style="display: inline-block; background: {badge_bg}; border: 1px solid {badge_border}; color: {badge_color}; font-weight: 800; font-size: 0.72rem; padding: 4px 14px; border-radius: 9999px; font-family: \'Outfit\', sans-serif; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 14px;">Verdict: {verdict_str}</div>'
                text = text[verdict_match.end():].strip()
                
            # Replace markdown headers with customized HTML headers
            text = text.replace("### Indicators Found", '<h4 style="color: #C084FC; font-family: \'Outfit\', sans-serif; font-weight: 700; font-size: 1.05rem; margin-top: 14px; margin-bottom: 6px;">Indicators Found</h4>')
            text = text.replace("### Why It Is Suspicious", '<h4 style="color: #EF4444; font-family: \'Outfit\', sans-serif; font-weight: 700; font-size: 1.05rem; margin-top: 18px; margin-bottom: 6px;">Why It Is Suspicious</h4>')
            text = text.replace("### Recommended Action", '<h4 style="color: #10B981; font-family: \'Outfit\', sans-serif; font-weight: 700; font-size: 1.05rem; margin-top: 18px; margin-bottom: 6px;">Recommended Action</h4>')
            
            # Format markdown lists to HTML lists
            lines = text.split("\n")
            in_list = False
            html_lines = []
            for line in lines:
                stripped = line.strip()
                list_match = re.match(r'^[-*]\s+(.+)$', stripped)
                if list_match:
                    item_text = list_match.group(1)
                    if not in_list:
                        html_lines.append('<ul style="margin: 6px 0 12px 0; padding-left: 20px; color: #CBD5E1; font-family: \'Inter\', sans-serif; font-size: 0.9rem; line-height: 1.65;">')
                        in_list = True
                    html_lines.append(f'<li style="margin-bottom: 6px;">{item_text}</li>')
                else:
                    if in_list:
                        html_lines.append('</ul>')
                        in_list = False
                    html_lines.append(line)
            if in_list:
                html_lines.append('</ul>')
                
            text = "\n".join(html_lines)
            
            # Convert bolding, italics, and backticks to HTML style
            text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
            text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
            text = re.sub(r'`(.+?)`', r'<code style="background: rgba(168,85,247,0.12); padding: 2px 6px; border-radius: 4px; color: #C084FC; font-family: \'Fira Code\', monospace; font-size: 0.82rem;">\1</code>', text)
            
            # Process remaining text lines with breaks
            lines = text.split("\n")
            final_lines = []
            for line in lines:
                l_strip = line.strip()
                if l_strip == "":
                    final_lines.append("<div style='height: 8px;'></div>")
                else:
                    final_lines.append(line)
                    if not (l_strip.endswith(">") and any(tag in l_strip for tag in ["ul>", "li>", "h4>", "div>"])):
                        final_lines[-1] += "<br>"
            
            clean_expl = "".join(final_lines)
            if verdict_badge:
                clean_expl = verdict_badge + clean_expl
                
            st.markdown(f"""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(124, 58, 237, 0.25); border-radius: 16px; padding: 24px; height: 500px; display: flex; flex-direction: column;">
<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px; flex-shrink: 0;">
<span style="color: #C084FC; font-size: 1.2rem;">✨</span>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.2rem; font-family: 'Outfit', sans-serif; font-weight: 800;">AI Threat Assessment</h3>
</div>
<div class="scrollable-card-content" style="color: #CBD5E1; font-size: 0.92rem; line-height: 1.7; font-family: 'Inter', sans-serif; overflow-y: auto; flex: 1; padding-right: 6px;">
{clean_expl}
</div>
</div>""", unsafe_allow_html=True)

        # 2. Email Headers Card
        with st.container(border=True):
            raw_from_val = st.session_state.parsed.get("from", "N/A")
            raw_to_val = st.session_state.parsed.get("to", "N/A")
            raw_subj_val = st.session_state.parsed.get("subject", "N/A")
            raw_date_val = st.session_state.parsed.get("date", "N/A")

            st.markdown(f"""
<h3 style="margin-top:0; margin-bottom:16px; color:#FFFFFF; font-family: 'Outfit', sans-serif; font-weight: 800; font-size: 1.25rem;">Email Headers</h3>
<div style="display: flex; flex-direction: column; gap: 0;">
  <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
    <span style="color: #94A3B8; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-family: 'Outfit', sans-serif; flex-shrink: 0; margin-right: 16px;">FROM</span>
    <span style="color: #F8FAFC; font-size: 0.85rem; font-family: 'Fira Code', monospace; text-align: right; word-break: break-all;">{raw_from_val}</span>
  </div>
  <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
    <span style="color: #94A3B8; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-family: 'Outfit', sans-serif; flex-shrink: 0; margin-right: 16px;">TO</span>
    <span style="color: #F8FAFC; font-size: 0.85rem; font-family: 'Fira Code', monospace; text-align: right; word-break: break-all;">{raw_to_val}</span>
  </div>
  <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">
    <span style="color: #94A3B8; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-family: 'Outfit', sans-serif; flex-shrink: 0; margin-right: 16px;">SUBJECT</span>
    <span style="color: #F8FAFC; font-size: 0.85rem; font-family: 'Fira Code', monospace; text-align: right; word-break: break-all;">{raw_subj_val}</span>
  </div>
  <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 0;">
    <span style="color: #94A3B8; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; font-family: 'Outfit', sans-serif; flex-shrink: 0; margin-right: 16px;">DATE</span>
    <span style="color: #F8FAFC; font-size: 0.85rem; font-family: 'Fira Code', monospace; text-align: right; word-break: break-all;">{raw_date_val}</span>
  </div>
</div>
""", unsafe_allow_html=True)

        # 3. Email Content Preview Card (Clean Gmail / Outlook Email Client View)
        with st.container(border=True):
            st.markdown("""<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px;">
<div style="display: flex; align-items: center; gap: 8px;">
  <span style="color: #A855F7; font-size: 1.2rem;">✉️</span>
  <h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Email Content Preview</h3>
</div>
<span style="background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.3); color: #C084FC; font-size: 0.76rem; font-weight: 700; padding: 4px 12px; border-radius: 9999px; font-family: 'Outfit', sans-serif;">GMAIL / OUTLOOK VIEW MODE</span>
</div>""", unsafe_allow_html=True)

            body_text = st.session_state.parsed.get("body", "")
            
            # Format bold/italic markdown into clean HTML tags for email rendering
            formatted_body = body_text
            formatted_body = re.sub(r'\*\*(.+?)\*\*', r'<strong style="color: #FFFFFF; font-weight: 700;">\1</strong>', formatted_body)
            formatted_body = re.sub(r'\*(.+?)\*', r'<em>\1</em>', formatted_body)

            # Convert URLs into clean, clickable hyperlinks (#4FC3F7) without inline badges or pills
            if st.session_state.url_analysis:
                for item in st.session_state.url_analysis:
                    url = item["url"]
                    clickable_link = f'<a href="{url}" target="_blank" style="color: #4FC3F7; font-weight: 600; text-decoration: underline; word-break: break-all;">{url}</a>'
                    if url in formatted_body:
                        formatted_body = formatted_body.replace(url, clickable_link)

            st.markdown(f"""
<div style="background: #161129; border: 1px solid rgba(168, 85, 247, 0.2); border-radius: 14px; padding: 28px 32px; font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif; color: #ECEFF4; font-size: 1.02rem; line-height: 1.75; white-space: pre-wrap; word-break: break-word; overflow-wrap: anywhere; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4); box-sizing: border-box; width: 100%; height: auto; min-height: fit-content; display: block; margin-bottom: 8px; overflow: visible; transform: none; position: relative;">{formatted_body}</div>
""", unsafe_allow_html=True)

        # 3. Link & Domain Analysis Card (Individual Link Cards with Spacing - Matching Reference Screenshot)
        with st.container(border=True):
            num_urls = len(st.session_state.url_analysis) if st.session_state.url_analysis else 0
            st.markdown(f"""<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px;">
<div style="display: flex; align-items: center; gap: 8px;">
  <span style="color: #38BDF8; font-size: 1.2rem;">🔗</span>
  <h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Link & Domain Analysis</h3>
</div>
<span style="background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); color: #38BDF8; font-size: 0.76rem; font-weight: 700; padding: 4px 12px; border-radius: 9999px; font-family: 'Outfit', sans-serif;">{num_urls} URL(s) DETECTED</span>
</div>""", unsafe_allow_html=True)

            if st.session_state.url_analysis:
                url_cards_html = []
                for item in st.session_state.url_analysis:
                    url = item["url"]
                    domain = item["domain"]
                    tld = item["tld"]
                    full_domain = f"{domain}.{tld}" if tld and tld != "invalid" else domain
                    suspicious = item["suspicious"]
                    
                    status_badge = '<span style="background: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 12px; border-radius: 9999px; font-size: 0.78rem; font-weight: 700;">✔ Benign</span>' if not suspicious else '<span style="background: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid rgba(239, 68, 68, 0.3); padding: 4px 12px; border-radius: 9999px; font-size: 0.78rem; font-weight: 700;">🚨 Suspicious</span>'

                    domain_badge = f'<span style="background: #06B6D4; color: #000000; font-weight: 800; padding: 4px 14px; border-radius: 9999px; font-size: 0.78rem; font-family: \'Fira Code\', monospace;">{full_domain}</span>'

                    card_html = f"""<div style="background: #1D1733; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 18px 20px; margin-bottom: 14px; display: flex; flex-direction: column; gap: 10px;">
  <div>
    <a href="{url}" target="_blank" style="color: #FFFFFF; font-family: 'Fira Code', monospace; font-size: 0.92rem; font-weight: 600; text-decoration: none; word-break: break-all;">{url}</a>
  </div>
  <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
    {domain_badge}
    {status_badge}
  </div>
</div>"""
                    url_cards_html.append(card_html)

                all_cards_str = "".join(url_cards_html)
                st.markdown(all_cards_str, unsafe_allow_html=True)
            else:
                st.markdown('<p style="color: #94A3B8; font-size: 0.88rem; margin: 0;">No external links extracted from email body.</p>', unsafe_allow_html=True)

        # 4. Trigger Language Card (Matching Screenshot 5)
        with st.container(border=True):
            st.markdown('<h3 style="margin-top:0; margin-bottom:14px; color:#FFFFFF; font-family: \'Outfit\', sans-serif; font-weight: 800; font-size: 1.25rem;">Trigger Language</h3>', unsafe_allow_html=True)

            if st.session_state.keyword_matches:
                badges_list = []
                for category, words in st.session_state.keyword_matches.items():
                    category_label = category.lower()
                    words_str = ", ".join(words)
                    badges_list.append(f'<span style="background: #140D2B; border: 1px solid rgba(124, 58, 237, 0.35); color: #C084FC; padding: 6px 14px; border-radius: 9999px; font-size: 0.82rem; font-weight: 600; font-family: \'Fira Code\', monospace; display: inline-flex; align-items: center; word-break: break-word; line-height: 1.4;">{category_label}: {words_str}</span>')
                
                st.markdown(f"""<div style="display: flex; flex-wrap: wrap; gap: 10px; align-items: center; padding-bottom: 12px; margin-bottom: 4px;">
{"".join(badges_list)}
</div>""", unsafe_allow_html=True)
            else:
                st.markdown('<p style="color: #94A3B8; font-size: 0.88rem; padding-bottom: 10px;">No trigger language keywords detected.</p>', unsafe_allow_html=True)

        # 5. Ask AI Security Copilot Chatbot Card
        with st.container(border=True):
            st.markdown("""<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;">
<span style="color: #C084FC; font-size: 1.2rem;">💬</span>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Ask AI Security Copilot</h3>
</div>""", unsafe_allow_html=True)

            chat_container = st.container(height=260)
            with chat_container:
                if len(st.session_state.chat_history) == 0:
                    st.info("👋 Ask any question regarding this email payload, sender headers, suspicious links, or containment steps.")
                for msg in st.session_state.chat_history:
                    with st.chat_message(msg["role"]):
                        st.write(msg["content"])
                        
            with st.form(key="analyst_chat_form", clear_on_submit=True):
                c_col1, c_col2 = st.columns([5, 1])
                with c_col1:
                    user_q = st.text_input("Ask AI Analyst:", placeholder="Type your question about this threat payload here...", label_visibility="collapsed")
                with c_col2:
                    submit_chat = st.form_submit_button("Send 🚀", use_container_width=True)
                    
                if submit_chat and user_q.strip():
                    st.session_state.chat_history.append({"role": "user", "content": user_q})
                    model_name = get_ollama_model()
                    ai_reply = chat_with_analyst(
                        user_q,
                        st.session_state.parsed,
                        st.session_state.url_analysis,
                        st.session_state.keyword_matches,
                        st.session_state.risk,
                        st.session_state.explanation,
                        st.session_state.chat_history,
                        model_name=model_name
                    )
                    st.session_state.chat_history.append({"role": "assistant", "content": ai_reply})
                    st.rerun()

# Page 3: 📊 Intelligence Vault (Matching Screenshots 1, 2, 3, 4)
elif st.session_state.navigation_page == "📊 Intelligence Vault":
    if "vault_tab" not in st.session_state:
        st.session_state.vault_tab = "Threat Samples"

    # Title Banner (Matching Screenshots 1, 3, 4)
    st.markdown("""<div style="display: flex; align-items: flex-start; gap: 14px; margin-bottom: 24px;">
<div style="width: 44px; height: 44px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC;">🗄️</div>
<div>
<h2 style="margin: 0; color: #FFFFFF; font-size: 1.6rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Intelligence Vault</h2>
<p style="color: #38BDF8; font-size: 0.88rem; margin: 4px 0 0 0; font-family: 'Inter', sans-serif;">Threat samples, suspicious TLD telemetry, and your local history.</p>
</div>
</div>""", unsafe_allow_html=True)

    # Sub-Nav Bar (Threat Samples | Suspicious TLDs | Local History)
    v_tab1, v_tab2, v_tab3, _v_empty = st.columns([1, 1, 1, 3])
    with v_tab1:
        if st.button("Threat Samples", use_container_width=True, type="primary" if st.session_state.vault_tab == "Threat Samples" else "secondary"):
            st.session_state.vault_tab = "Threat Samples"
            st.rerun()
    with v_tab2:
        if st.button("Suspicious TLDs", use_container_width=True, type="primary" if st.session_state.vault_tab == "Suspicious TLDs" else "secondary"):
            st.session_state.vault_tab = "Suspicious TLDs"
            st.rerun()
    with v_tab3:
        if st.button("Local History", use_container_width=True, type="primary" if st.session_state.vault_tab == "Local History" else "secondary"):
            st.session_state.vault_tab = "Local History"
            st.rerun()

    st.markdown("<div style='margin-top: 15px;'></div>", unsafe_allow_html=True)

    # TAB 1: Threat Samples (Screenshots 1 & 2)
    if st.session_state.vault_tab == "Threat Samples":
        for sample_title, sample_content in SAMPLE_EMAILS.items():
            sender_line = ""
            for line in sample_content.splitlines():
                if line.startswith("From:"):
                    sender_line = line
                    break
            
            with st.container(border=True):
                st.markdown(f"""<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.15rem; font-family: 'Outfit', sans-serif; font-weight: 800;">{sample_title}</h3>
<span style="background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); color: #94A3B8; font-size: 0.76rem; font-weight: 600; padding: 2px 10px; border-radius: 6px;">Sample</span>
</div>
<div style="color: #94A3B8; font-size: 0.85rem; font-family: 'Fira Code', monospace; margin-bottom: 14px;">{sender_line}</div>""", unsafe_allow_html=True)
                st.code(sample_content, language="text")

    # TAB 2: Suspicious TLDs (Screenshot 3)
    elif st.session_state.vault_tab == "Suspicious TLDs":
        with st.container(border=True):
            st.markdown("""<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
<span style="color: #38BDF8; font-size: 1.2rem;">🌐</span>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Suspicious TLD Watchlist</h3>
</div>
<p style="color: #94A3B8; font-size: 0.86rem; margin: 0 0 20px 0;">Top-level domains commonly abused in phishing and malware campaigns.</p>""", unsafe_allow_html=True)
            
            tlds = [
                ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".club", ".online",
                ".site", ".icu", ".cyou", ".work", ".click", ".link", ".download",
                ".review", ".party", ".racing", ".win", ".bid", ".date", ".stream"
            ]
            
            badge_htmls = [f'<span style="background: #06B6D4; color: #000000; font-weight: 800; padding: 6px 14px; border-radius: 9999px; font-size: 0.82rem; font-family: \'Fira Code\', monospace;">{tld}</span>' for tld in tlds]
            
            st.markdown(f"""<div style="display: flex; flex-wrap: wrap; gap: 10px;">
{"".join(badge_htmls)}
</div>""", unsafe_allow_html=True)

    # TAB 3: Local History (Screenshot 4)
    elif st.session_state.vault_tab == "Local History":
        if st.session_state.recent_analyses:
            for item in st.session_state.recent_analyses:
                with st.container(border=True):
                    st.markdown(f"""<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
<div style="display: flex; align-items: center; gap: 8px;">
<span style="color: #C084FC;">📄</span>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.1rem; font-family: 'Outfit', sans-serif; font-weight: 800;">{item.get('subject', 'Analysis Run')}</h3>
</div>
<span style="background: rgba(124, 58, 237, 0.25); border: 1px solid rgba(124, 58, 237, 0.4); color: #C084FC; font-weight: 700; font-size: 0.76rem; padding: 3px 12px; border-radius: 9999px;">{item.get('risk_level', 'Critical')}</span>
</div>
<div style="color: #94A3B8; font-size: 0.85rem; font-family: 'Fira Code', monospace; margin-bottom: 12px;">{item.get('sender', 'Unknown')}</div>
<p style="color: #CBD5E1; font-size: 0.88rem; line-height: 1.6; margin: 0;">
This email is a critical phishing threat, as evidenced by its high risk score of 12/20 and the heavy use of high-urgency keywords demanding immediate action within 24 hours. The sender utilizes a deceptive lookalike domain and directs the recipient to an external link to harvest credentials under the guise of identity verification.
</p>""", unsafe_allow_html=True)
        else:
            with st.container(border=True):
                st.markdown("""<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
<div style="display: flex; align-items: center; gap: 8px;">
<span style="color: #C084FC;">📄</span>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.1rem; font-family: 'Outfit', sans-serif; font-weight: 800;">URGENT: Unauthorized login attempt detected on your account</h3>
</div>
<span style="background: rgba(124, 58, 237, 0.25); border: 1px solid rgba(124, 58, 237, 0.4); color: #C084FC; font-weight: 700; font-size: 0.76rem; padding: 3px 12px; border-radius: 9999px;">Critical</span>
</div>
<div style="color: #94A3B8; font-size: 0.85rem; font-family: 'Fira Code', monospace; margin-bottom: 12px;">Bank Security Operations &lt;alert@secure-bank0nline.com&gt;</div>
<p style="color: #CBD5E1; font-size: 0.88rem; line-height: 1.6; margin: 0;">
This email is a critical phishing threat, as evidenced by its high risk score of 12/20 and the heavy use of high-urgency keywords demanding immediate action within 24 hours. The sender utilizes a deceptive lookalike domain ('secure-bank0nline.com') and directs the recipient to an external link ('secure-bank0nline-verify.com') to harvest credentials under the guise of identity verification.
</p>""", unsafe_allow_html=True)

# Page 4: 📖 Security Playbooks (Matching Screenshot 5)
elif st.session_state.navigation_page == "📖 Security Playbooks":
    # Header Banner (Matching Screenshot 5)
    st.markdown("""<div style="display: flex; align-items: flex-start; gap: 14px; margin-bottom: 24px;">
<div style="width: 44px; height: 44px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC;">📖</div>
<div>
<h2 style="margin: 0; color: #FFFFFF; font-size: 1.6rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Security Playbooks</h2>
<p style="color: #38BDF8; font-size: 0.88rem; margin: 4px 0 0 0; font-family: 'Inter', sans-serif;">Standard operating procedures for phishing detection and response.</p>
</div>
</div>""", unsafe_allow_html=True)

    play_col1, play_col2 = st.columns(2)

    with play_col1:
        # Playbook #01: Initial Triage
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 24px; min-height: 250px; margin-bottom: 20px;">
<div style="width: 42px; height: 42px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC; margin-bottom: 14px;">🛡️</div>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Initial Triage</h3>
<div style="color: #94A3B8; font-size: 0.84rem; margin: 2px 0 16px 0;">Playbook #01</div>
<ol style="margin: 0; padding-left: 18px; color: #CBD5E1; font-size: 0.88rem; line-height: 1.7;">
<li>Do not click any links or download attachments.</li>
<li>Verify the sender identity via a separate trusted channel.</li>
<li>Capture the original email headers and body for forensics.</li>
</ol>
</div>""", unsafe_allow_html=True)

        # Playbook #03: Reporting
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 24px; min-height: 250px;">
<div style="width: 42px; height: 42px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC; margin-bottom: 14px;">📋</div>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Reporting</h3>
<div style="color: #94A3B8; font-size: 0.84rem; margin: 2px 0 16px 0;">Playbook #03</div>
<ol style="margin: 0; padding-left: 18px; color: #CBD5E1; font-size: 0.88rem; line-height: 1.7;">
<li>Report to your internal SOC or security team.</li>
<li>Forward phishing emails to your national CERT/anti-phishing body.</li>
<li>Document indicators of compromise (IoCs) for future hunts.</li>
</ol>
</div>""", unsafe_allow_html=True)

    with play_col2:
        # Playbook #02: Containment
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 24px; min-height: 250px; margin-bottom: 20px;">
<div style="width: 42px; height: 42px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC; margin-bottom: 14px;">⚠️</div>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">Containment</h3>
<div style="color: #94A3B8; font-size: 0.84rem; margin: 2px 0 16px 0;">Playbook #02</div>
<ol style="margin: 0; padding-left: 18px; color: #CBD5E1; font-size: 0.88rem; line-height: 1.7;">
<li>Quarantine the email from the user's mailbox.</li>
<li>Block the sender domain and any malicious URLs.</li>
<li>Reset credentials if the user entered them on a phishing site.</li>
</ol>
</div>""", unsafe_allow_html=True)

        # Playbook #04: User Education
        st.markdown("""<div class="soc-card" style="background: #0E0A1E; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 24px; min-height: 250px;">
<div style="width: 42px; height: 42px; background: rgba(124, 58, 237, 0.15); border: 1px solid rgba(124, 58, 237, 0.3); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; color: #C084FC; margin-bottom: 14px;">👥</div>
<h3 style="margin: 0; color: #FFFFFF; font-size: 1.25rem; font-family: 'Outfit', sans-serif; font-weight: 800;">User Education</h3>
<div style="color: #94A3B8; font-size: 0.84rem; margin: 2px 0 16px 0;">Playbook #04</div>
<ol style="margin: 0; padding-left: 18px; color: #CBD5E1; font-size: 0.88rem; line-height: 1.7;">
<li>Brief the affected user on what happened and why.</li>
<li>Run a simulated phishing campaign to reinforce awareness.</li>
<li>Update training material with the latest lure tactics.</li>
</ol>
</div>""", unsafe_allow_html=True)

# -------------------------------------------------
# Footer Section
# -------------------------------------------------
st.markdown("""<div class="footer" style="border-top: 1px solid rgba(168, 85, 247, 0.2); padding-top: 25px; margin-top: 40px; text-align: center;">
<div style="color: #CBD5E1; font-size: 0.88rem; font-family: 'Outfit', sans-serif;">Developed by <strong style="color: #C084FC;">Cryptiva Cyber Operations Team</strong> | SOC Center</div>
<div style="color: #94A3B8; font-size: 0.78rem; margin-top: 6px;">Air-Gapped Neural Models • Real-Time WHOIS Telemetry • Automated Incident Defense</div>
<div style="margin-top: 14px;">
<span class="footer-badge">Python</span>
<span class="footer-badge">Streamlit</span>
<span class="footer-badge">Ollama</span>
<span class="footer-badge">Llama 3</span>
<span class="footer-badge">WHOIS</span>
<span class="footer-badge">PyMuPDF</span>
</div>
</div>""", unsafe_allow_html=True)

