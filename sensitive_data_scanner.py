#!/usr/bin/env python3
"""
Local Sensitive Data Scanner (sensitive_data_scanner.py)
Page-by-page sensitive-data scanner for PDF, DOCX, and XLSX files.

The scanner never modifies its input files. The GUI can optionally create a
separate redacted copy after a successful scan.
All processing is local. The only network call is to a local Ollama server
(127.0.0.1), which is required to analyze and summarize every page.

Layers:
  1. Rules   : regex + validators (SSN, card/Luhn, IBAN, email, phone, DOB, ...)
  2. NER     : optional, Presidio (if installed) for names / addresses
  3. LLM     : required, local Ollama (e.g. qwen3:4b) for contextual items and summaries

Usage:
  python sensitive_data_scanner.py                         # desktop GUI
  python sensitive_data_scanner.py FILE_OR_FOLDER [more ...] -o report_dir
  python sensitive_data_scanner.py /media/usb --model qwen3:4b -o reports
  python sensitive_data_scanner.py doc.pdf --ner

Finding values are masked by default. The report itself is still sensitive.
"""
import argparse
from dataclasses import dataclass, asdict, field
import hashlib
import html
import ipaddress
import json
import os
import queue
import re
import shutil
import sys
import tempfile
import threading
import time
from typing import Callable, Optional
from urllib.parse import urlsplit
import zipfile
from pathlib import Path

TOOL_NAME = "Local Sensitive Data Scanner"
BANNER = ("Offline screening tool: lists possible sensitive data for human review. "
          "It may miss items. A result of 'no findings' is not a guarantee that a file is safe.")

# ----------------------------------------------------------------- limits
MAX_FILE_MB = 100
MAX_PAGES = 500
MAX_DOCX_UNCOMPRESSED_MB = 300     # zip-bomb guard
DOCX_CHARS_PER_PAGE = 3000         # docx has no real pages; chunk by size
LLM_CHARS_PER_REQUEST = 6000
LLM_CHUNK_OVERLAP = 300
SUPPORTED = {".pdf", ".docx", ".xlsx"}
REPORT_UNSUPPORTED = {".xls", ".doc", ".csv", ".ppt", ".pptx", ".txt", ".rtf"}  # listed as "not scanned"
REFUSED = {".docm", ".dotm", ".xlsm", ".pptm"}   # macro-enabled: refuse

# Category IDs are used by the GUI, CLI, rule filters, and masking pipeline.
SENSITIVE_CATEGORIES = (
    ("government_identifiers", "Government identifiers"),
    ("payment_cards", "Card data"),
    ("payment_banking", "Payment and banking"),
    ("login_secrets", "Login and security secrets"),
    ("personal_identifiers", "Personal identifiers"),
    ("identifying_documents", "Identifying document references"),
    ("health_status_information", "Health status information"),
    ("staff_discipline", "Staff discipline"),
    ("hr_private_data", "HR private data"),
    ("genetic_biometric", "Genetic and biometric information"),
    ("criminal_information", "Criminal information"),
    ("employment_financial", "Employment and financial records"),
)
SENSITIVE_CATEGORY_IDS = frozenset(category_id for category_id, _ in SENSITIVE_CATEGORIES)
LEGACY_CATEGORY_ALIASES = {"health_information": "health_status_information"}


def _enabled_category_ids(args) -> set[str]:
    disabled = set(getattr(args, "disabled_categories", ()) or ())
    disabled.update(
        LEGACY_CATEGORY_ALIASES[category]
        for category in tuple(disabled)
        if category in LEGACY_CATEGORY_ALIASES
    )
    return SENSITIVE_CATEGORY_IDS - disabled


# ----------------------------------------------------------------- findings


@dataclass
class Finding:
    page: int
    category: str
    masked: str
    source: str            # rule | ner | llm
    confidence: str        # high | medium | low
    context: str = ""      # masked snippet around the match
    detected_text: str = field(default="", repr=False)


def _finding_dict(finding: Finding, include_detected_text: bool = False) -> dict:
    data = asdict(finding)
    if not include_detected_text:
        data.pop("detected_text", None)
    return data


def mask(value: str, keep: int = 4) -> str:
    v = value.strip()
    digits = re.sub(r"\D", "", v)
    if len(digits) >= 6:  # number-like: keep last 4 digits
        return "*" * (len(v) - keep) + v[-keep:] if len(v) > keep else "*" * len(v)
    if len(v) <= 3:
        return "*" * len(v)
    return v[0] + "*" * (len(v) - 2) + v[-1]


def masked_context(text: str, start: int, end: int, masked: str, width: int = 30) -> str:
    a = max(0, start - width)
    b = min(len(text), end + width)
    snippet = text[a:start] + masked + text[end:b]
    return re.sub(r"\s+", " ", snippet).strip()


# ----------------------------------------------------------------- validators
def luhn_ok(num: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", num)]
    if not 13 <= len(digits) <= 19:
        return False
    s = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        s += d
    return s % 10 == 0


def ssn_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 9:
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def itin_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 9 or d[0] != "9":
        return False
    g = int(d[3:5])
    return 50 <= g <= 65 or 70 <= g <= 88 or 90 <= g <= 92 or 94 <= g <= 99


def iban_ok(s: str) -> bool:
    s = re.sub(r"\s", "", s).upper()
    if not 15 <= len(s) <= 34:
        return False
    r = s[4:] + s[:4]
    n = "".join(str(int(c, 36)) for c in r)
    return int(n) % 97 == 1


def aba_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 9:
        return False
    w = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    return sum(int(a) * b for a, b in zip(d, w)) % 10 == 0


# ----------------------------------------------------------------- rule layer
KEYWORD_NEAR = lambda kw: r"(?i:" + kw + r")[^\n]{0,25}?"

RULES = [
    # (category, regex, validator, confidence)
    ("US SSN", r"(?<!\d)\d{3}[- ]\d{2}[- ]\d{4}(?!\d)", ssn_ok, "high"),
    ("US ITIN", r"(?<!\d)9\d{2}[- ]\d{2}[- ]\d{4}(?!\d)", itin_ok, "high"),
    ("US SSN (no separators, labelled)",
     KEYWORD_NEAR(r"ssn|social security(?: number)?|soc\.? sec\.?") + r"(?<!\d)(\d{9})(?!\d)",
     ssn_ok, "medium"),
    ("Payment card number", r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)", luhn_ok, "high"),
    ("IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b", iban_ok, "high"),
    ("Bank routing number (labelled)",
     KEYWORD_NEAR(r"routing|aba|rtn") + r"(?<!\d)(\d{9})(?!\d)", aba_ok, "medium"),
    ("Bank account number (labelled)",
     KEYWORD_NEAR(r"account (?:no|number|#)|acct\.? ?(?:no|number|#)?") + r"(?<!\d)(\d{8,17})(?!\d)",
     None, "medium"),
    ("Email address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", None, "medium"),
    ("Phone number",
     r"(?<!\d)(?:\+?1[ -.]?)?\(?\d{3}\)?[ -.]\d{3}[ -.]\d{4}(?!\d)", None, "low"),
    ("Date of birth (labelled)",
     KEYWORD_NEAR(r"dob|date of birth|birth ?date|born") +
     r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2}|[A-Z][a-z]{2,8}\.? \d{1,2},? \d{4})",
     None, "high"),
    ("Passport number (labelled)",
     KEYWORD_NEAR(r"passport(?: no| number| #)?") + r"\b([A-Z0-9]{6,9})\b", None, "medium"),
    ("Driver's license (labelled)",
     KEYWORD_NEAR(r"driver'?s? licen[sc]e(?: no| number| #)?|DL ?#?") + r"\b([A-Z0-9-]{6,15})\b",
     None, "medium"),
    ("Tax ID / EIN (labelled)",
     KEYWORD_NEAR(r"ein|tax id|tin|itin") + r"(\d{2}-?\d{7}|\d{3}-?\d{2}-?\d{4})", None, "medium"),
    ("Salary / compensation (labelled)",
     KEYWORD_NEAR(r"salary|base pay|compensation|annual pay|hourly rate|bonus") +
     r"(\$ ?\d[\d,]*(?:\.\d{2})?(?: ?[kK])?|\d{2,3}(?:,\d{3})+(?:\.\d{2})?|\d{5,7}(?:\.\d{2})?)", None, "medium"),
]

RULE_CATEGORY_GROUPS = {
    "US SSN": "government_identifiers",
    "US ITIN": "government_identifiers",
    "US SSN (no separators, labelled)": "government_identifiers",
    "Payment card number": "payment_cards",
    "IBAN": "payment_banking",
    "Bank routing number (labelled)": "payment_banking",
    "Bank account number (labelled)": "payment_banking",
    "Email address": "personal_identifiers",
    "Phone number": "personal_identifiers",
    "Date of birth (labelled)": "personal_identifiers",
    "Passport number (labelled)": "government_identifiers",
    "Driver's license (labelled)": "government_identifiers",
    "Tax ID / EIN (labelled)": "government_identifiers",
    "Salary / compensation (labelled)": "employment_financial",
    "HR-related term": "employment_financial",
    "Possible person name": "personal_identifiers",
}

# Labeled values are deliberately conservative; free-form content still needs human review.
ADDITIONAL_RULES = [
    ("Aadhaar number (labelled)",
     KEYWORD_NEAR(r"aadhaar|aadhar") +
     r"(?<!\d)(\d{4}[ -]?\d{4}[ -]?\d{4})(?!\d)",
     "government_identifiers", "high"),
    ("PAN card number (labelled)",
     KEYWORD_NEAR(r"PAN(?: card)?(?: number| no| #)?") +
     r"\b([A-Z]{5}\d{4}[A-Z])\b",
     "government_identifiers", "high"),
    ("National ID number (labelled)",
     KEYWORD_NEAR(r"national (?:ID|identity)(?: number| no| #)?") +
     r"\b([A-Z0-9-]{6,24})\b",
     "government_identifiers", "medium"),
    ("CVV/CVC or PIN (labelled)",
     KEYWORD_NEAR(r"cvv|cvc|security code|pin(?: code)?") + r"(\d{3,8})",
     "payment_cards", "high"),
    ("Password or passcode (labelled)",
     KEYWORD_NEAR(r"password|passphrase|passcode|login credential") +
     r"([^\s,;]{4,100})",
     "login_secrets", "high"),
    ("One-time or recovery code (labelled)",
     KEYWORD_NEAR(r"one[- ]time (?:code|password)|otp|recovery code|backup code") +
     r"([A-Z0-9-]{4,40})",
     "login_secrets", "high"),
    ("API key or access token (labelled)",
     KEYWORD_NEAR(r"api key|access token|refresh token|secret key|client secret") +
     r"([A-Za-z0-9._~+/=-]{8,160})",
     "login_secrets", "high"),
    ("Private key block",
     r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END "
     r"(?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
     "login_secrets", "high"),
    ("Crypto seed phrase (labelled)",
     KEYWORD_NEAR(r"seed phrase|mnemonic phrase|recovery phrase|wallet backup phrase") +
     r"((?:[A-Za-z]+\s+){11,23}[A-Za-z]+)",
     "login_secrets", "high"),
    ("Home or mailing address (labelled)",
     KEYWORD_NEAR(r"home address|residential address|mailing address|street address") +
     r"\s*[:=-]?\s*([^\n]{6,120})",
     "personal_identifiers", "medium"),
    ("Phone number (labelled)",
     KEYWORD_NEAR(r"phone|telephone|mobile|cell(?: phone)?") +
     r"\s*[:=-]?\s*(\+?\d[\d\s().-]{6,20}\d)",
     "personal_identifiers", "medium"),
    ("Signature (labelled)",
     KEYWORD_NEAR(r"signature|signed by") +
     r"\s*[:=-]?\s*([^\n]{2,100})",
     "personal_identifiers", "low"),
    ("Sensitive document reference",
     r"\b(?:tax returns?|bank statements?|payslips?|pay ?stubs?|passport copy|"
     r"identity documents?|ID scans?|application forms?)\b",
     "identifying_documents", "medium"),
    ("Health information (labelled)",
     KEYWORD_NEAR(r"diagnosis|medical condition|prescription|medication|"
                  r"medical history|mental health|disability|patient record") +
     r"\s*[:=-]?\s*([^\n]{3,160})",
     "health_status_information", "medium"),
    ("Staff disciplinary record (labelled)",
     KEYWORD_NEAR(r"disciplinary (?:action|record|proceeding)|written warning|"
                  r"performance improvement plan|PIP|grievance|harassment complaint|"
                  r"termination record|employee investigation") +
     r"\s*[:=-]?\s*([^\n]{2,160})",
     "staff_discipline", "medium"),
    ("Private HR record (labelled)",
     KEYWORD_NEAR(r"employee (?:file|record|ID|number|data)|personnel file|"
                  r"HR record|payroll record|salary details|compensation details|"
                  r"benefits record|leave record|performance review|performance rating") +
     r"\s*[:=-]?\s*([^\n]{2,160})",
     "hr_private_data", "medium"),
    ("Genetic or biometric information (labelled)",
     KEYWORD_NEAR(r"DNA result|genetic test|biometric (?:data|template)|"
                  r"fingerprint|facial template|voiceprint") +
     r"\s*[:=-]?\s*([^\n]{3,160})",
     "genetic_biometric", "medium"),
    ("Criminal record (labelled)",
     KEYWORD_NEAR(r"criminal record|criminal conviction|offence|offense|arrest|"
                  r"conviction|court record") + r"\s*[:=-]?\s*([^\n]{2,160})",
     "criminal_information", "medium"),
    ("Employment or financial record (labelled)",
     KEYWORD_NEAR(r"salary history|credit report|credit score|outstanding debt|"
                  r"investment account") +
     r"\s*[:=-]?\s*([^\n]{2,160})",
     "employment_financial", "medium"),
]

# HR terminology is also used to decide when contextual local-model analysis is useful.
STAFF_DISCIPLINE_TERMS = re.compile(
    r"\b(performance improvement plan|PIP\b|disciplin\w*|terminat(?:ed|ion)|"
    r"written warning|grievance|harassment complaint|background check|"
    r"exit interview|investigation)\b", re.I)
HR_PRIVATE_TERMS = re.compile(
    r"\b(employee id|employee number|employee file|employee record|personnel file|"
    r"HR record|payroll|garnishment|severance|salary|compensation|benefits record|"
    r"leave record|performance review|performance rating)\b", re.I)
HR_TERMS = re.compile(
    STAFF_DISCIPLINE_TERMS.pattern + "|" + HR_PRIVATE_TERMS.pattern +
    r"|medical leave|FMLA|workers'? comp(?:ensation)?|disability accommodation",
    re.I,
)


def _rule_category_group(category: str) -> Optional[str]:
    if category in RULE_CATEGORY_GROUPS:
        return RULE_CATEGORY_GROUPS[category]
    return next(
        (group for name, _, group, _ in ADDITIONAL_RULES if name == category),
        None,
    )


def _rule_matches(
    text: str, min_start: int = 0, keep_emails: bool = False,
    enabled_categories: Optional[set[str]] = None,
    ignore_emails: bool = False,
) -> list[tuple[int, int, str, str, str]]:
    matches = []
    seen = set()
    for category, pattern, validator, confidence in RULES:
        if category == "Email address" and ignore_emails:
            continue
        if enabled_categories is not None and _rule_category_group(category) not in enabled_categories:
            continue
        for match in re.finditer(pattern, text):
            group = 1 if match.re.groups else 0
            value = match.group(group)
            if validator and not validator(value):
                continue
            start, end = match.span(group)
            if end <= min_start or (start, end) in seen:
                continue
            seen.add((start, end))
            masked = value if keep_emails and category == "Email address" else mask(value)
            matches.append((start, end, category, masked, confidence))
    for category, pattern, group_category, confidence in ADDITIONAL_RULES:
        if enabled_categories is not None and group_category not in enabled_categories:
            continue
        for match in re.finditer(pattern, text, re.I):
            group = 1 if match.re.groups else 0
            value = match.group(group)
            start, end = match.span(group)
            if end <= min_start or (start, end) in seen:
                continue
            seen.add((start, end))
            matches.append((start, end, category, mask(value), confidence))
    if enabled_categories is None or "personal_identifiers" in enabled_categories:
        for start, end in _labelled_name_spans(text):
            if end > min_start and (start, end) not in seen:
                seen.add((start, end))
                value = text[start:end]
                matches.append((start, end, "Possible person name", mask(value), "low"))
    context_term_rules = (
        (STAFF_DISCIPLINE_TERMS, "Staff discipline", "staff_discipline"),
        (HR_PRIVATE_TERMS, "HR private data", "hr_private_data"),
    )
    for pattern, category, group in context_term_rules:
        if enabled_categories is not None and group not in enabled_categories:
            continue
        for match in pattern.finditer(text):
            if match.end() > min_start:
                matches.append((
                    match.start(), match.end(), category,
                    match.group(0).lower(), "low"))
    other_hr_terms = re.compile(
        r"\b(medical leave|FMLA|workers'? comp(?:ensation)?|"
        r"disability accommodation)\b", re.I)
    if enabled_categories is None or "employment_financial" in enabled_categories:
        for match in other_hr_terms.finditer(text):
            if match.end() > min_start:
                matches.append((
                    match.start(), match.end(), "HR-related term",
                    match.group(0).lower(), "low"))
    return matches


def _ner_matches(text: str) -> list[tuple[int, int, str, float]]:
    global _analyzer
    if _analyzer is None:
        try:
            from presidio_analyzer import AnalyzerEngine
            _analyzer = AnalyzerEngine()
        except Exception as exc:
            print(f"[warn] --ner requested but Presidio unavailable: {exc}", file=sys.stderr)
            _analyzer = False
    if not _analyzer:
        return []
    entities = [
        "PERSON", "US_DRIVER_LICENSE", "US_PASSPORT",
        "MEDICAL_LICENSE", "US_BANK_NUMBER",
    ]
    return [
        (match.start, match.end, match.entity_type, match.score)
        for match in _analyzer.analyze(
            text=text, language="en", entities=entities)
        if match.score >= 0.5
    ]


def _ner_category_group(entity_type: str) -> Optional[str]:
    if entity_type == "PERSON":
        return "personal_identifiers"
    if entity_type in {"US_DRIVER_LICENSE", "US_PASSPORT"}:
        return "government_identifiers"
    if entity_type == "MEDICAL_LICENSE":
        return "health_status_information"
    if entity_type == "US_BANK_NUMBER":
        return "payment_banking"
    return None


def _sensitive_spans(
    text: str, args, mask_hr_terms: bool = True,
) -> list[tuple[int, int]]:
    # HR wording ("terminated", "written warning") is context, not a value. The model needs to read it,
    # so the LLM sanitizer passes mask_hr_terms=False. Redaction keeps the old behaviour (True).
    keep_emails = getattr(args, "keep_emails", False)
    ignore_emails = getattr(args, "ignore_emails", False)
    enabled_categories = _enabled_category_ids(args)
    spans = [
        (start, end)
        for start, end, category, *_ in _rule_matches(
            text, keep_emails=keep_emails,
            enabled_categories=enabled_categories, ignore_emails=ignore_emails)
        if (mask_hr_terms
            or category not in {"HR-related term", "Staff discipline", "HR private data"})
        and not (keep_emails and category == "Email address")
    ]
    if getattr(args, "ner", False):
        spans.extend(
            (start, end) for start, end, entity_type, _ in _ner_matches(text)
            if _ner_category_group(entity_type) in enabled_categories
        )
    merged = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _replace_spans_with_x(text: str, spans: list[tuple[int, int]]) -> tuple[str, int]:
    chars = list(text)
    for start, end in spans:
        chars[start:end] = "X" * (end - start)
    return "".join(chars), len(spans)


def run_rules(
    text: str, page: int, min_start: int = 0, keep_emails: bool = False,
    enabled_categories: Optional[set[str]] = None,
    ignore_emails: bool = False,
) -> list[Finding]:
    """Scan `text`. Matches lying entirely before `min_start` (the overlap from the previous page)
    are ignored; matches crossing the boundary are kept. Context snippets are cut from a copy of the
    text in which EVERY finding has been masked, so one finding never leaks another value."""
    raw = _rule_matches(
        text, min_start, keep_emails=keep_emails,
        enabled_categories=enabled_categories, ignore_emails=ignore_emails)
    # build fully masked text (sensitive spans only; HR terms are left readable)
    context_categories = {"HR-related term", "Staff discipline", "HR private data"}
    spans = sorted((a, b, mk) for a, b, c, mk, _ in raw if c not in context_categories)
    pieces, pos, shift_map = [], 0, []
    for a, b, mk in spans:
        if a < pos:        # overlapping span: skip, already masked
            continue
        pieces.append(text[pos:a]); pieces.append(mk)
        shift_map.append((a, b, len(mk)))
        pos = b
    pieces.append(text[pos:])
    mtext = "".join(pieces)

    def new_off(off: int) -> int:
        d = 0
        for a, b, ml in shift_map:
            if b <= off:
                d += ml - (b - a)
            else:
                break
        return off + d

    out = []
    for a, b, cat, mk, conf in raw:
        na = new_off(a)
        nb = na + (len(mk) if cat != "HR-related term" else (b - a))
        ctx = re.sub(r"\s+", " ", mtext[max(0, na - 30):nb + 30]).strip()
        out.append(Finding(
            page, cat, mk, "rule", conf, ctx, detected_text=text[a:b]))
    return out


# ----------------------------------------------------------------- NER layer
_analyzer = None


def run_ner(
    text: str, page: int, enabled_categories: Optional[set[str]] = None,
) -> list[Finding]:
    out = []
    for start, end, entity_type, score in _ner_matches(text):
        if (enabled_categories is not None
                and _ner_category_group(entity_type) not in enabled_categories):
            continue
        val = text[start:end]
        mk = mask(val)
        out.append(Finding(
            page,
            entity_type.replace("_", " ").title(),
            mk,
            "ner",
            "medium" if score >= 0.7 else "low",
            masked_context(text, start, end, mk),
            detected_text=text[start:end],
        ))
    return out


# ----------------------------------------------------------------- LLM layer
LLM_CATEGORIES = [
    "HR or employment action about a person",
    "Health or medical information about a person",
    "Pay or compensation of a specific person",
    "Staff disciplinary information about an employee",
    "Private HR information about an employee",
    "Background check, investigation or legal matter about a person",
    "Other personal data about a specific person",
]
LLM_CATEGORY_GROUPS = {
    "HR or employment action about a person": "staff_discipline",
    "Health or medical information about a person": "health_status_information",
    "Pay or compensation of a specific person": "hr_private_data",
    "Staff disciplinary information about an employee": "staff_discipline",
    "Private HR information about an employee": "hr_private_data",
    "Background check, investigation or legal matter about a person": "criminal_information",
    "Other personal data about a specific person": "personal_identifiers",
}


def _enabled_llm_categories(enabled_categories: set[str]) -> list[str]:
    return [
        category for category in LLM_CATEGORIES
        if LLM_CATEGORY_GROUPS[category] in enabled_categories
    ]

_LLM_INTRO = """You are a privacy-preserving document reviewer. The page text below has had
recognized values from selected categories replaced with Xs or [REDACTED]. Categories disabled for
this scan may remain visible. If email addresses are present, email preservation may have been
requested; they may remain intact. Never guess, reconstruct, or repeat masked values.

Task 1 - summary: identify the page's most important points, up to 8. Return a JSON array
of short bullet strings, ordered by importance. Do not include names, dates, locations, exact
amounts, identifiers, direct quotes, or other identifying details.
"""

LLM_PROMPT_SUMMARY = _LLM_INTRO + """
Return JSON only: {"summary_points":["first point","second point"]}

PAGE TEXT:
"""

LLM_PROMPT_FULL = _LLM_INTRO + """
Task 2 - findings: report ONLY statements that reveal something sensitive about one specific,
identifiable individual (a masked name, or a role that clearly means one person) in these
categories: """ + "; ".join(LLM_CATEGORIES) + """.

Use "Staff disciplinary information about an employee" for a person's disciplinary process,
warning, grievance, or investigation. Use "Private HR information about an employee" for
employee records, compensation, benefits, payroll, or leave details. Use "Health or medical
information about a person" for that person's diagnosis, condition, treatment, or health status.

These are NOT findings. Return an empty findings list for them:
- company or organization financials, statistics, strategy, mission or marketing text
- lists of board members, officers or staff with their titles
- the organization's own address, website or contact details
- general descriptions of HR policy, audit, compliance or security that name no individual

Examples:
Text: "Net income was XXXXX million and our members grew 11 percent."
Answer: {"summary_points":["Reports yearly financial results."],"findings":[]}
Text: "Board of Directors: XXXXX XXXXX, Chairperson; XXXXX XXXXX, Treasurer"
Answer: {"summary_points":["Lists governance roles."],"findings":[]}
Text: "XXXXX XXXXX was placed on a performance improvement plan after a written warning."
Answer: {"summary_points":["Describes an employee review."],"findings":[{"category":"HR or employment action about a person","evidence":"placed on a performance improvement plan","confidence":"high"}]}

For every finding, "evidence" must be an exact phrase of at most 6 words copied from the page text.
If you cannot copy an exact phrase, do not report the finding. When in doubt, return an empty list.
Return JSON only:
{"summary_points":["..."],"findings":[{"category":"...","evidence":"...","confidence":"high|medium|low"}]}

PAGE TEXT:
"""

LLM_SCHEMA_SUMMARY = {
    "type": "object",
    "properties": {
        "summary_points": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 8,
        },
    },
    "required": ["summary_points"],
}
LLM_SCHEMA_FULL = {
    "type": "object",
    "properties": {
        "summary_points": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 8,
        },
        "findings": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "enum": LLM_CATEGORIES},
                "evidence": {"type": "string"},
                "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            },
            "required": ["category", "evidence", "confidence"],
        }},
    },
    "required": ["summary_points", "findings"],
}
LLM_SCHEMA_DOCUMENT = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "main_points": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 3,
        },
    },
    "required": ["description", "main_points"],
}


def _sanitize_summary(points, original_text: str, args) -> str:
    if isinstance(points, str):
        points = [points]
    if not isinstance(points, list):
        points = []
    cleaned_points = []
    enabled_categories = _enabled_category_ids(args)
    spans = _sensitive_spans(original_text, args)
    if "personal_identifiers" in enabled_categories:
        spans.extend(_possible_name_spans(original_text))
    spans = sorted(set(spans))
    for point in points:
        if not isinstance(point, str):
            continue
        point = re.sub(r"\s+", " ", point).strip()
        for start, end in reversed(spans):
            value = original_text[start:end].strip()
            if value:
                point = re.sub(
                    re.escape(value), "[redacted]", point, flags=re.IGNORECASE)
        if "personal_identifiers" in enabled_categories:
            point = re.sub(
                r"\b[A-Z][a-z]+(?:[ '-][A-Z][a-z]+)+\b",
                "[redacted name]",
                point,
            )
        if ("personal_identifiers" in enabled_categories
                and not getattr(args, "ignore_emails", False)
                and not getattr(args, "keep_emails", False)):
            point = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                           "[redacted]", point, flags=re.IGNORECASE)
        point = point[:300].strip(" -\t")
        if point and point not in cleaned_points:
            cleaned_points.append(point)
        if len(cleaned_points) == 8:
            break
    if not cleaned_points:
        cleaned_points = ["Page summary unavailable; review the page manually."]
    return "\n".join(
        f"{index}. {point}" for index, point in enumerate(cleaned_points, 1))


def _sanitize_document_summary(data: dict, args) -> dict:
    description_line = _sanitize_summary(
        [data.get("description", "")], "", args).splitlines()[0]
    description = description_line.split(". ", 1)[-1]
    points = _sanitize_summary(data.get("main_points", []), "", args)
    point_lines = points.splitlines()
    return {
        "description": description,
        "main_points": [
            line.split(". ", 1)[1] for line in point_lines[:3] if ". " in line
        ],
    }


def _summary_batches(items: list[str], max_chars: int = 4500) -> list[list[str]]:
    batches = []
    current = []
    current_size = 0
    for item in items:
        item_size = len(item) + 1
        if current and current_size + item_size > max_chars:
            batches.append(current)
            current = []
            current_size = 0
        current.append(item)
        current_size += item_size
    if current:
        batches.append(current)
    return batches


def _summarize_document_batch(
    items: list[str], model: str, host: str, timeout: int,
) -> dict:
    import urllib.error
    import urllib.request

    prompt = (
        "Summarize the document using only these per-page summaries. Identify the document's "
        "overall type/topic and purpose in one brief description, then give its three most "
        "important distinct points (or fewer if there are fewer). Do not include names, dates, "
        "locations, exact amounts, identifiers, direct quotes, or identifying details. "
        "Return JSON only with description and main_points (an array of at most 3 strings).\n\n"
        + "\n".join(items)
    )

    def call(output_format):
        body = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": output_format,
            "think": False,
            "options": {"temperature": 0, "num_ctx": 4096},
        }).encode()
        request = urllib.request.Request(
            host.rstrip("/") + "/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with _ollama_opener().open(request, timeout=timeout) as response:
            return json.loads(response.read())

    try:
        try:
            response = call(LLM_SCHEMA_DOCUMENT)
        except urllib.error.HTTPError as exc:
            if exc.code != 400:
                raise
            response = call("json")
        data = json.loads(response.get("response", "{}"))
    except Exception as exc:
        raise RuntimeError(f"Document summary request failed: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Ollama returned an invalid document summary.")
    description = data.get("description")
    points = data.get("main_points")
    if not isinstance(description, str) or not isinstance(points, list):
        raise RuntimeError("Ollama returned an invalid document summary.")
    points = [point for point in points if isinstance(point, str)][:3]
    return {"description": description, "main_points": points}


def summarize_document(
    page_summaries: list[dict], model: str, host: str, timeout: int, args,
) -> dict:
    items = [
        f"Page {page['page']}:\n{page['summary']}"
        for page in page_summaries
    ]
    if not items:
        return {
            "description": "No page summaries are available.",
            "main_points": [],
        }

    while True:
        batches = _summary_batches(items)
        summaries = [
            _summarize_document_batch(batch, model, host, timeout)
            for batch in batches
        ]
        if len(summaries) == 1:
            return _sanitize_document_summary(summaries[0], args)
        items = [
            f"Document section {index}:\n"
            f"Description: {summary['description']}\n"
            "Main points:\n"
            + "\n".join(
                f"{point_number}. {point}"
                for point_number, point in enumerate(summary["main_points"], 1))
            for index, summary in enumerate(summaries, 1)
        ]


_NAME_LABEL = re.compile(
    r"(?i:\b(?:name|contact|employee|patient|customer|client|applicant|author|student|"
    r"owner|manager|doctor|prepared by|attn)\s*(?:name)?\s*[:=-]?\s*"
    r")([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})"
)
_TITLE_CASE_PAIR = re.compile(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b")
_NON_NAME_PAIRS = {
    "Annual Salary", "Annual Review", "Background Check", "Bank Account",
    "Date Birth", "Date Of", "Employee Handbook", "Employee Number",
    "Human Resources", "Medical Leave", "Payment Card", "Performance Review",
    "Performance Improvement", "Personal Information", "Social Security",
    "Tax Return", "Written Warning",
}


def _possible_name_spans(text: str) -> list[tuple[int, int]]:
    spans = _labelled_name_spans(text)
    for match in _TITLE_CASE_PAIR.finditer(text):
        if match.group(0) not in _NON_NAME_PAIRS:
            spans.append(match.span())
    return spans


def _labelled_name_spans(text: str) -> list[tuple[int, int]]:
    return [match.span(1) for match in _NAME_LABEL.finditer(text)]


def _sanitize_page_for_llm(text: str, args) -> str:
    spans = _sensitive_spans(text, args, mask_hr_terms=False)
    if "personal_identifiers" in _enabled_category_ids(args):
        spans.extend(_possible_name_spans(text))
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    sanitized, _ = _replace_spans_with_x(text, merged)
    if ("personal_identifiers" in _enabled_category_ids(args)
            and not getattr(args, "ignore_emails", False)
            and not getattr(args, "keep_emails", False)):
        sanitized = re.sub(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "[REDACTED]",
            sanitized,
            flags=re.IGNORECASE,
        )
    return sanitized


def _llm_text_chunks(text: str) -> list[str]:
    if not text:
        return [""]
    chunks = []
    start = 0
    while start < len(text):
        end = min(start + LLM_CHARS_PER_REQUEST, len(text))
        if end < len(text):
            boundary = text.rfind(" ", start + LLM_CHARS_PER_REQUEST // 2, end)
            if boundary > start:
                end = boundary
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = max(end - LLM_CHUNK_OVERLAP, start + 1)
    return chunks


# Fix 4: only ask the model for contextual findings when the page shows a signal.
_LLM_TRIGGERS = re.compile(
    r"\b(diagnos\w*|prescri\w+|medical (?:condition|record|history|leave)|"
    r"health (?:condition|information|record)|sick leave|maternity|paternity|disabilit\w+|"
    r"accommodations?|salary|bonus|raise|promotion|demot\w+|resign\w*|dismiss\w*|fired|"
    r"probation|complaint|lawsuit|settlement|arrest\w*|convict\w*|harass\w*|discriminat\w+|"
    r"appraisal|disciplin\w+)\b", re.I)
_PERSON_HINT = re.compile(
    r"\b(he|she|his|her|him|employee|applicant|candidate|patient|claimant)\b", re.I)


def _llm_gate(text: str, findings: list) -> bool:
    """True when the contextual-findings question is worth asking for this page."""
    if any(f.source != "llm" and f.category != "HR-related term"
           and f.confidence in ("high", "medium") for f in findings):
        return True                      # an identifier is on the page: context matters
    if not (HR_TERMS.search(text) or _LLM_TRIGGERS.search(text)):
        return False                     # no HR / health / pay wording at all
    return bool(_possible_name_spans(text) or _PERSON_HINT.search(text))


def _ollama_opener():
    import urllib.request

    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirectHandler())


def ensure_ollama_available(host: str, model: str, timeout: int) -> None:
    import urllib.request

    if not is_local_ollama_host(host):
        raise ValueError("Refusing non-local Ollama host: documents must not leave this machine.")
    req = urllib.request.Request(host.rstrip("/") + "/api/tags")
    try:
        with _ollama_opener().open(req, timeout=timeout) as response:
            data = json.loads(response.read())
    except Exception as exc:
        raise RuntimeError(
            f"Required local Ollama service is unavailable at {host}: {exc}") from exc
    model_names = [
        item.get("name", "") for item in data.get("models", [])
        if isinstance(item, dict)
    ] if isinstance(data, dict) else []
    if model not in model_names:
        raise RuntimeError(
            f"Required Ollama model '{model}' is not installed. "
            f"Available models: {', '.join(model_names) or 'none'}.")


def _norm_words(text: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", text.lower()).split())


def _display_evidence(phrase: str) -> str:
    """Evidence comes from sanitized text, but mask anything name- or number-like anyway."""
    shown = []
    for i, word in enumerate(phrase.split()):
        bare = word.strip(".,;:()[]\"'")
        if re.fullmatch(r"[Xx]{3,}", bare) or bare.upper() == "REDACTED":
            shown.append("[name]")
        elif i > 0 and re.fullmatch(r"[A-Z][a-z]+", bare):
            shown.append("[name]")
        elif re.search(r"\d{3,}", bare):
            shown.append("[number]")
        else:
            shown.append(word)
    return " ".join(shown)


def _verify_llm_findings(
    raw_findings, sanitized_text: str, page: int,
    allowed_categories: Optional[set[str]] = None,
) -> list[Finding]:
    """Fix 1: keep a model finding only if its evidence phrase really appears on the page."""
    haystack = f" {_norm_words(sanitized_text)} "
    stop_words = {
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
        "has", "in", "is", "it", "of", "on", "or", "that", "the", "this",
        "to", "was", "were", "with",
    }
    out, seen = [], set()
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        category = item.get("category")
        if category not in LLM_CATEGORIES:
            continue
        if allowed_categories is not None and category not in allowed_categories:
            continue
        phrase = " ".join(str(item.get("evidence", "")).split()[:8])
        needle = _norm_words(phrase)
        meaningful = [
            token for token in needle.split()
            if not re.fullmatch(r"x+", token)
            and token != "redacted"
            and token not in stop_words
        ]
        if not meaningful:
            continue
        if f" {needle} " not in haystack:
            continue                       # not found on the page: hallucination, drop
        shown = _display_evidence(phrase)
        if (category, shown) in seen:
            continue
        seen.add((category, shown))
        conf = item.get("confidence", "low")
        out.append(Finding(page, category, shown, "llm",
                           conf if conf in ("high", "medium", "low") else "low", ""))
    return out


def run_llm(
    text: str,
    page: int,
    model: str,
    host: str,
    timeout: int,
    args,
    want_findings: bool = True,
) -> tuple[list[Finding], str]:
    import urllib.error
    import urllib.request
    if not is_local_ollama_host(host):
        raise ValueError("Refusing non-local Ollama host: documents must not leave this machine.")

    enabled_categories = _enabled_category_ids(args)
    allowed_llm_categories = set(_enabled_llm_categories(enabled_categories))
    want_findings = want_findings and bool(allowed_llm_categories)
    sanitized_chunks = _llm_text_chunks(_sanitize_page_for_llm(text, args))
    if want_findings:
        prompt_prefix = LLM_PROMPT_FULL.replace(
            "; ".join(LLM_CATEGORIES),
            "; ".join(category for category in LLM_CATEGORIES
                      if category in allowed_llm_categories),
        )
        schema = {
            **LLM_SCHEMA_FULL,
            "properties": {
                **LLM_SCHEMA_FULL["properties"],
                "findings": {
                    "type": "array",
                    "items": {
                        **LLM_SCHEMA_FULL["properties"]["findings"]["items"],
                        "properties": {
                            **LLM_SCHEMA_FULL["properties"]["findings"]["items"]["properties"],
                            "category": {
                                "type": "string",
                                "enum": sorted(allowed_llm_categories),
                            },
                        },
                    },
                },
            },
        }
    else:
        prompt_prefix = LLM_PROMPT_SUMMARY
        schema = LLM_SCHEMA_SUMMARY

    def call(fmt, prompt):
        body = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": fmt,
            "think": False,
            "options": {"temperature": 0, "num_ctx": 4096},
        }).encode()
        req = urllib.request.Request(host.rstrip("/") + "/api/generate", data=body,
                                     headers={"Content-Type": "application/json"})
        with _ollama_opener().open(req, timeout=timeout) as r:
            return json.loads(r.read())

    out: list[Finding] = []
    summary_points = []
    for chunk in sanitized_chunks:
        prompt = prompt_prefix + chunk
        try:
            try:
                resp = call(schema, prompt)
            except urllib.error.HTTPError as e:
                if e.code != 400:
                    raise
                resp = call("json", prompt)  # Ollama without JSON-schema support
            data = json.loads(resp.get("response", "{}"))
        except Exception as e:
            raise RuntimeError(
                f"Required Ollama analysis failed on page {page}: {e}") from e
        if not isinstance(data, dict):
            raise RuntimeError(f"Ollama returned invalid JSON on page {page}.")

        chunk_summary = data.get("summary_points", [])
        if isinstance(chunk_summary, list):
            summary_points.extend(chunk_summary)
        if want_findings:
            findings = data.get("findings", [])
            if not isinstance(findings, list):
                raise RuntimeError(
                    f"Ollama returned invalid findings on page {page}.")
            out.extend(_verify_llm_findings(
                findings, chunk, page, allowed_llm_categories))
    summary = _sanitize_summary(summary_points, text, args)
    return out, summary


def is_local_ollama_host(host: str) -> bool:
    try:
        parsed = urlsplit(host)
        hostname = parsed.hostname
        if (parsed.scheme.lower() != "http" or not hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment):
            return False
        if hostname.lower() == "localhost":
            return True
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


# ----------------------------------------------------------------- readers
def pages_pdf(path: Path):
    """Prefer pypdfium2 (permissive license); fall back to PyMuPDF (AGPL) if that is what is installed."""
    try:
        import pypdfium2 as pdfium
    except ImportError:
        pdfium = None
    if pdfium:
        try:
            doc = pdfium.PdfDocument(str(path))
        except pdfium.PdfiumError as e:
            raise ValueError(f"cannot open PDF (password-protected or corrupt): {e}")
        n = len(doc)
        if n > MAX_PAGES:
            raise ValueError(f"too many pages ({n} > {MAX_PAGES})")
        for i in range(n):
            page = doc[i]
            text = page.get_textpage().get_text_range()
            has_images = any(page.get_objects(
                filter=[pdfium.raw.FPDF_PAGEOBJ_IMAGE]))
            warnings = []
            if has_images or len(text.strip()) < 20:
                try:
                    image = page.render(scale=200 / 72).to_pil()
                    ocr_text, ocr_error = _ocr_image(image)
                except Exception as exc:
                    ocr_text = ""
                    ocr_error = f"OCR rendering failed: {type(exc).__name__}."
                if ocr_text:
                    text = _combine_ocr_text(text, ocr_text)
                elif has_images:
                    warnings.append(
                        "Page contains image content that could not be OCR-scanned.")
                if ocr_error and has_images:
                    warnings.append(ocr_error)
            yield i + 1, text, False, warnings
        return
    import fitz  # PyMuPDF fallback
    doc = fitz.open(path)
    if doc.needs_pass:
        raise ValueError("PDF is password-protected")
    if len(doc) > MAX_PAGES:
        raise ValueError(f"too many pages ({len(doc)} > {MAX_PAGES})")
    for i, page in enumerate(doc, 1):
        text = page.get_text("text")
        has_images = bool(page.get_images(full=True))
        warnings = []
        if has_images or len(text.strip()) < 20:
            try:
                import io
                from PIL import Image
                img = Image.open(
                    io.BytesIO(page.get_pixmap(dpi=200).tobytes("png")))
                ocr_text, ocr_error = _ocr_image(img)
            except Exception as exc:
                ocr_text = ""
                ocr_error = f"OCR rendering failed: {type(exc).__name__}."
            if ocr_text:
                text = _combine_ocr_text(text, ocr_text)
            elif has_images:
                warnings.append(
                    "Page contains image content that could not be OCR-scanned.")
            if ocr_error and has_images:
                warnings.append(ocr_error)
        yield i, text, False, warnings


def _combine_ocr_text(extracted: str, ocr_text: str) -> str:
    if not extracted.strip():
        return ocr_text
    extracted_lines = {
        re.sub(r"\W+", "", line).casefold()
        for line in extracted.splitlines()
        if re.sub(r"\W+", "", line)
    }
    new_lines = [
        line for line in ocr_text.splitlines()
        if re.sub(r"\W+", "", line).casefold() not in extracted_lines
    ]
    return extracted + ("\n" + "\n".join(new_lines) if new_lines else "")


def _ocr_image(img) -> tuple[str, Optional[str]]:
    try:
        import pytesseract
    except ImportError:
        return "", "OCR support is not installed."
    try:
        return pytesseract.image_to_string(img), None
    except pytesseract.TesseractNotFoundError:
        return "", "Tesseract OCR is not installed or not available."
    except Exception as exc:
        return "", f"OCR failed: {type(exc).__name__}."


def pages_docx(path: Path):
    with zipfile.ZipFile(path) as z:
        total = sum(i.file_size for i in z.infolist())
        if total > MAX_DOCX_UNCOMPRESSED_MB * 1024 * 1024:
            raise ValueError("docx expands too large (possible zip bomb)")
    import docx
    d = docx.Document(str(path))
    import xml.etree.ElementTree as ET

    parts: list[str] = []
    for p in d.paragraphs:
        parts.append(p.text)
    for t in d.tables:
        for row in t.rows:
            parts.append(" | ".join(c.text for c in row.cells))
    for s in d.sections:
        for hf in (s.header, s.footer):
            parts.extend(p.text for p in hf.paragraphs)
    # comments / core properties
    cp = d.core_properties
    parts.append(f"[metadata] author={cp.author} last_modified_by={cp.last_modified_by} title={cp.title}")
    namespace = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    has_comments_or_textboxes = False
    with zipfile.ZipFile(path) as archive:
        for member in archive.namelist():
            if not member.startswith("word/") or not member.endswith(".xml"):
                continue
            is_comments = member == "word/comments.xml"
            is_document_part = (
                member == "word/document.xml"
                or re.fullmatch(r"word/(?:header|footer)\d+\.xml", member)
            )
            if not is_comments and not is_document_part:
                continue
            root = ET.fromstring(archive.read(member))
            if is_comments:
                for comment in root.iter(f"{namespace}comment"):
                    comment_text = "\n".join(
                        "".join(text_node.text or "" for text_node in paragraph.iter(f"{namespace}t"))
                        for paragraph in comment.iter(f"{namespace}p")
                    ).strip()
                    if comment_text:
                        parts.append(f"[comment] {comment_text}")
                        has_comments_or_textboxes = True
            if is_document_part:
                for textbox in root.iter(f"{namespace}txbxContent"):
                    textbox_text = "\n".join(
                        "".join(text_node.text or "" for text_node in paragraph.iter(f"{namespace}t"))
                        for paragraph in textbox.iter(f"{namespace}p")
                    ).strip()
                    if textbox_text:
                        parts.append(f"[text box] {textbox_text}")
                        has_comments_or_textboxes = True
    coverage_warnings = []
    if has_comments_or_textboxes:
        coverage_warnings.append(
            "Comments or text boxes were scanned; redacted copies may retain content in those areas.")
    chunk, n, buf = [], 0, []
    page = 1
    for line in parts:
        buf.append(line)
        n += len(line) + 1
        if n >= DOCX_CHARS_PER_PAGE:
            yield page, "\n".join(buf), False, coverage_warnings
            coverage_warnings = []
            page += 1
            buf, n = [], 0
    if buf:
        yield page, "\n".join(buf), False, coverage_warnings


def _cell_str(v) -> str:
    import datetime as _dt
    if v is None:
        return ""
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return str(int(v)) if v.is_integer() and abs(v) < 1e18 else repr(v)
    if isinstance(v, (_dt.datetime, _dt.date)):
        return v.isoformat()
    return str(v).strip()


_NUMLIKE = re.compile(r"[-\d.,$%/: ]+")


def pages_xlsx(path: Path):
    """Each sheet is split into chunks of about DOCX_CHARS_PER_PAGE characters.
    Rows are written as 'Header: value | Header: value' so the labelled rules work on columns.
    Hidden sheets are read too (and flagged). Formula text and cached cell values are read."""
    with zipfile.ZipFile(path) as z:
        total = sum(i.file_size for i in z.infolist())
        if total > MAX_DOCX_UNCOMPRESSED_MB * 1024 * 1024:
            raise ValueError("xlsx expands too large (possible zip bomb)")
    import openpyxl
    wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
    formula_wb = openpyxl.load_workbook(
        str(path), read_only=True, data_only=False)
    page = 0
    try:
        p = wb.properties
        page += 1
        yield page, f"[metadata] creator={p.creator} last_modified_by={p.lastModifiedBy} title={p.title}", False, []
        for ws in wb.worksheets:
            hidden = ws.sheet_state != "visible"
            formula_ws = formula_wb[ws.title]
            header, buf, buf_warnings, n = None, [], [], 0
            formula_rows = formula_ws.iter_rows(values_only=True)
            for r_idx, row in enumerate(ws.iter_rows(values_only=True), 1):
                formula_row = next(formula_rows)
                vals = [_cell_str(c) for c in row]
                formulas = [
                    str(cell) if isinstance(cell, str) and cell.startswith("=") else ""
                    for cell in formula_row
                ]
                row_warnings = []
                for col_idx, formula in enumerate(formulas):
                    if formula:
                        cached = vals[col_idx] if col_idx < len(vals) else ""
                        if cached:
                            vals[col_idx] = f"{cached} [formula: {formula}]"
                        else:
                            vals[col_idx] = f"[formula result unavailable] {formula}"
                            row_warnings.append(
                                "One or more spreadsheet formula results are unavailable and could not be verified.")
                if not any(vals):
                    continue
                if header is None and not any(_NUMLIKE.fullmatch(v) for v in vals if v):
                    # Preserve the candidate header row as scan content too:
                    # all-text rows can be data rather than column labels.
                    header = vals
                    cells = [v for v in vals if v]
                elif header:
                    cells = [f"{header[i]}: {v}" if i < len(header) and header[i] else v
                             for i, v in enumerate(vals) if v]
                else:
                    cells = [v for v in vals if v]
                line = " | ".join(cells)
                buf.append(line)
                buf_warnings.extend(row_warnings)
                n += len(line) + 1
                if n >= DOCX_CHARS_PER_PAGE:
                    page += 1
                    if page > MAX_PAGES:
                        raise ValueError("workbook too large (too many chunks)")
                    yield page, "\n".join(buf), hidden, list(dict.fromkeys(buf_warnings))
                    buf, buf_warnings, n = [], [], 0
            if buf:
                page += 1
                if page > MAX_PAGES:
                    raise ValueError("workbook too large (too many chunks)")
                yield page, "\n".join(buf), hidden, list(dict.fromkeys(buf_warnings))
            elif hidden:
                page += 1
                yield page, "", hidden, []
    finally:
        wb.close()
        formula_wb.close()


# ----------------------------------------------------------------- scanning
def merge(findings: list[Finding]) -> list[Finding]:
    """Collapse identical (page, category, masked); upgrade confidence if 2+ sources agree."""
    order = {"low": 0, "medium": 1, "high": 2}
    key = {}
    for f in findings:
        k = (f.page, f.category.lower(), f.masked)
        if k in key:
            cur = key[k]
            if f.source not in cur.source.split("+"):
                cur.source += "+" + f.source
                if order[cur.confidence] < 2:
                    cur.confidence = "high" if order[f.confidence] >= 1 else cur.confidence
        else:
            key[k] = f
    return sorted(key.values(), key=lambda x: (x.page, -order[x.confidence], x.category))


def scan_file(
    path: Path,
    args,
    on_page: Optional[Callable[[int, list[dict], str, str], None]] = None,
) -> dict:
    t0 = time.time()
    ext = path.suffix.lower()
    result = {"file": path.name, "sha256": "", "pages_scanned": 0, "findings": [],
              "page_summaries": [], "document_summary": None,
              "document_summary_error": None, "clean_pages": [],
              "coverage_warnings": [], "error": None, "seconds": 0}
    if ext in REFUSED:
        result["error"] = "macro-enabled Office file: refused"
        return result
    if ext not in SUPPORTED:
        result["error"] = "unsupported type - NOT scanned (convert to PDF/DOCX/XLSX and scan again)"
        return result
    if path.stat().st_size > MAX_FILE_MB * 1024 * 1024:
        result["error"] = f"file larger than {MAX_FILE_MB} MB"
        return result
    result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    reader = {".pdf": pages_pdf, ".docx": pages_docx, ".xlsx": pages_xlsx}[ext]
    all_f: list[Finding] = []
    prev_tail = ""
    hidden_seen = False
    try:
        for pno, text, hidden_sheet, page_warnings in reader(path):
            result["pages_scanned"] += 1
            result["coverage_warnings"].extend(page_warnings)
            no_text = None
            if ext == ".pdf" and len(text.strip()) < 20:
                no_text = Finding(pno, "Page has no readable text (scanned image? OCR unavailable or failed) - review manually",
                                  "n/a", "rule", "medium", "")
            # small overlap so items split across a page boundary are still seen
            window = prev_tail + "\n" + text
            f = run_rules(
                window,
                pno,
                min_start=len(prev_tail) + 1 if prev_tail else 0,
                keep_emails=getattr(args, "keep_emails", False),
                enabled_categories=_enabled_category_ids(args),
                ignore_emails=getattr(args, "ignore_emails", False),
            )
            if getattr(args, "ner", False):
                f += run_ner(text, pno, _enabled_category_ids(args))
            context_categories_enabled = bool(
                _enabled_llm_categories(_enabled_category_ids(args)))
            ask_findings = context_categories_enabled and (
                bool(getattr(args, "llm_all", False)) or _llm_gate(text, f))
            context_analysis = (
                "Analyzed" if ask_findings
                else "Signal-gated" if context_categories_enabled
                else "Disabled"
            )
            llm_findings, page_summary = run_llm(
                text, pno, args.model, args.host, args.llm_timeout, args,
                want_findings=ask_findings)
            f += llm_findings
            prev_tail = text[-120:] if ext != ".xlsx" else ""
            if no_text:
                f.append(no_text)
            if hidden_sheet and not hidden_seen:
                hidden_seen = True
                f.append(Finding(
                    pno, "Hidden sheet present - review manually",
                    "n/a", "rule", "medium", ""))
            page_f = merge(f)
            # Fix 3: a finding from the model alone is never "high". It rises to "medium" only when a
            # rule/NER finding or contextual HR-term hit on the same page backs it up.
            backed = any(x.source != "llm" and (x.confidence in ("high", "medium")
                                                or x.category in {
                                                    "HR-related term",
                                                    "Staff discipline",
                                                    "HR private data",
                                                }) for x in page_f)
            for x in page_f:
                if x.source == "llm":
                    x.confidence = "medium" if backed and x.confidence in ("high", "medium") else "low"
            if not page_f:
                result["clean_pages"].append(pno)
            all_f += page_f
            result["page_summaries"].append({
                "page": pno,
                "summary": page_summary,
                "context_analysis": context_analysis,
                "coverage_warnings": page_warnings,
            })
            if on_page:
                on_page(
                    pno,
                    [_finding_dict(x, include_detected_text=True) for x in page_f],
                    page_summary,
                    context_analysis,
                )
            if args.verbose:
                print(f"  page {pno}: {len(page_f)} finding(s)", file=sys.stderr)
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    if result["page_summaries"] and not result["error"]:
        try:
            result["document_summary"] = summarize_document(
                result["page_summaries"],
                args.model,
                args.host,
                args.llm_timeout,
                args,
            )
        except Exception as e:
            result["document_summary_error"] = f"{type(e).__name__}: {e}"
    result["findings"] = [_finding_dict(x) for x in merge(all_f)]
    result["coverage_warnings"] = list(dict.fromkeys(result["coverage_warnings"]))
    result["seconds"] = round(time.time() - t0, 1)
    return result


def _redact_labeled_value(label: str, value: str, args) -> tuple[str, int]:
    prefix = f"{label}: " if label else ""
    spans = _sensitive_spans(prefix + value, args)
    value_start = len(prefix)
    value_spans = [
        (max(start, value_start) - value_start, min(end, len(prefix + value)) - value_start)
        for start, end in spans
        if end > value_start and start < len(prefix + value)
    ]
    return _replace_spans_with_x(value, value_spans)


def _redact_paragraph(paragraph, spans: list[tuple[int, int]]) -> int:
    if not spans:
        return 0
    paragraph_text = paragraph.text
    text_nodes = []
    text_tags = {
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t": None,
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}tab": "\t",
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}br": "\n",
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cr": "\n",
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}noBreakHyphen": "\u2011",
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}softHyphen": "\u00ad",
    }

    def collect_text_nodes(element):
        for child in element:
            if child.tag == "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p":
                continue
            if child.tag in text_tags:
                symbol = text_tags[child.tag]
                node_text = (child.text or "") if symbol is None else symbol
                text_nodes.append((child, node_text))
            else:
                collect_text_nodes(child)

    collect_text_nodes(paragraph._p)
    if "".join(value for _, value in text_nodes) != paragraph_text:
        raise ValueError(
            "Cannot safely map a detected DOCX match to the document's text nodes.")

    mask_positions = [False] * len(paragraph_text)
    for start, end in spans:
        mask_positions[start:end] = [True] * (end - start)
    offset = 0
    for node, original in text_nodes:
        updated = "".join(
            "X" if mask_positions[offset + index] else char
            for index, char in enumerate(original))
        if updated != original:
            if node.tag in {
                "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}tab",
                "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}br",
                "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}cr",
                "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}noBreakHyphen",
                "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}softHyphen",
            }:
                node.tag = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"
                node.attrib.clear()
            node.text = updated
        offset += len(original)
    return len(spans)


def _redact_cell_spans(cell, spans: list[tuple[int, int]]) -> int:
    if not spans:
        return 0
    redacted = 0
    cell_offset = 0
    for paragraph in cell.paragraphs:
        paragraph_end = cell_offset + len(paragraph.text)
        paragraph_spans = [
            (max(start, cell_offset) - cell_offset,
             min(end, paragraph_end) - cell_offset)
            for start, end in spans
            if end > cell_offset and start < paragraph_end
        ]
        redacted += _redact_paragraph(paragraph, paragraph_spans)
        cell_offset = paragraph_end + 1
    return redacted


def _pdf_match_rects(page, value: str):
    rects = page.search_for(value)
    if rects:
        return rects

    target_tokens = re.findall(r"[a-z0-9]+", value.casefold())
    if not target_tokens:
        return []

    words = page.get_text("words")
    flattened = []
    for word in words:
        word_tokens = re.findall(r"[a-z0-9]+", str(word[4]).casefold())
        flattened.extend((token, word[:4]) for token in word_tokens)

    found = []
    for start in range(len(flattened) - len(target_tokens) + 1):
        if [token for token, _ in flattened[start:start + len(target_tokens)]] == target_tokens:
            found.extend(rect for _, rect in flattened[start:start + len(target_tokens)])
    unique_rects = []
    seen_rects = set()
    for rect in found:
        key = tuple(round(float(value), 3) for value in rect)
        if key not in seen_rects:
            seen_rects.add(key)
            unique_rects.append(rect)
    return unique_rects


def _redact_pdf(source: Path, destination: Path, args) -> int:
    try:
        import pymupdf as fitz
    except ImportError as exc:
        raise RuntimeError(
            "PDF redaction requires optional PyMuPDF. Install it with "
            "'python -m pip install PyMuPDF' after checking its AGPL license."
        ) from exc

    doc = fitz.open(str(source))
    try:
        scanned_pages = iter(pages_pdf(source))
        redacted_matches = 0
        for page_number, page in enumerate(doc, 1):
            try:
                scanned_page_number, text, _, _ = next(scanned_pages)
            except StopIteration:
                break
            if scanned_page_number != page_number:
                raise ValueError("PDF page sequence changed during redaction.")
            spans = _sensitive_spans(text, args)
            if not spans:
                continue
            texts = [text[start:end] for start, end in spans]
            redaction_rects = []
            for value in dict.fromkeys(texts):
                rects = _pdf_match_rects(page, value)
                if not rects:
                    raise ValueError(
                        f"Could not map a detected PDF match on page {page_number} "
                        "to selectable text coordinates. It may be OCR-only or "
                        "formatted differently by the PDF reader. No redacted "
                        "copy was saved.")
                # PyMuPDF can return multiple rectangles for one search string
                # when it wraps across lines, and repeated occurrences also
                # produce one rectangle apiece. Redact every returned rectangle.
                redaction_rects.extend(rects)

            for rect in redaction_rects:
                page.add_redact_annot(
                    rect,
                    text="X",
                    fontname="helv",
                    fontsize=8,
                    fill=(1, 1, 1),
                    text_color=(0, 0, 0),
                    cross_out=False,
                )
            page.apply_redactions(images=2, graphics=0)
            redacted_matches += len(spans)

        doc.save(str(destination), garbage=4, deflate=True)
        return redacted_matches
    finally:
        doc.close()


def _redact_docx(source: Path, destination: Path, args) -> int:
    import docx

    document = docx.Document(str(source))
    redacted_matches = 0

    page = 1
    for paragraph in document.paragraphs:
        redacted_matches += _redact_paragraph(
            paragraph, _sensitive_spans(paragraph.text, args))
        page += 1

    for table in document.tables:
        for row in table.rows:
            cells = row.cells
            row_text = " | ".join(cell.text for cell in cells)
            row_spans = _sensitive_spans(row_text, args)
            offset = 0
            seen_cells = set()
            for cell in cells:
                cell_text = cell.text
                cell_id = id(cell._tc)
                if cell_id not in seen_cells:
                    cell_spans = [
                        (max(start, offset) - offset,
                         min(end, offset + len(cell_text)) - offset)
                        for start, end in row_spans
                        if end > offset and start < offset + len(cell_text)
                    ]
                    redacted_matches += _redact_cell_spans(cell, cell_spans)
                    seen_cells.add(cell_id)
                offset += len(cell_text) + 3
            page += 1

    for section in document.sections:
        for container in (section.header, section.footer):
            for paragraph in container.paragraphs:
                redacted_matches += _redact_paragraph(
                    paragraph, _sensitive_spans(paragraph.text, args))
                page += 1

    properties = document.core_properties
    for label, attribute in (
        ("author", "author"),
        ("last_modified_by", "last_modified_by"),
        ("title", "title"),
    ):
        value = getattr(properties, attribute)
        masked, count = _redact_labeled_value(label, value or "", args)
        if count:
            setattr(properties, attribute, masked)
            redacted_matches += count

    document.save(str(destination))
    return redacted_matches


def _redact_xlsx(source: Path, destination: Path, args) -> int:
    import openpyxl

    values_wb = openpyxl.load_workbook(
        str(source), read_only=False, data_only=True, keep_links=False)
    workbook = openpyxl.load_workbook(
        str(source), read_only=False, data_only=False, keep_links=False)
    redacted_matches = 0
    try:
        for sheet in workbook.worksheets:
            values_sheet = values_wb[sheet.title]
            header = None
            for row_idx, row in enumerate(sheet.iter_rows(), 1):
                values_row = values_sheet[row_idx]
                vals = [_cell_str(cell.value) for cell in values_row]
                is_header_row = False
                if header is None and vals and not any(
                    _NUMLIKE.fullmatch(value) for value in vals if value
                ):
                    header = vals
                    is_header_row = True
                for col_idx, cell in enumerate(row):
                    cached_value = _cell_str(values_row[col_idx].value)
                    formula_value = (
                        str(cell.value) if isinstance(cell.value, str)
                        and cell.value.startswith("=") else ""
                    )
                    label = (
                        header[col_idx]
                        if header and not is_header_row and col_idx < len(header)
                        else ""
                    )
                    if cached_value:
                        masked_value, count = _redact_labeled_value(
                            label, cached_value, args)
                        if count:
                            cell.value = masked_value
                            redacted_matches += count
                            continue
                    if formula_value:
                        masked_formula, count = _redact_labeled_value(
                            label, formula_value, args)
                        if count:
                            cell.value = masked_formula
                            redacted_matches += count

        properties = workbook.properties
        for label, attribute in (
            ("creator", "creator"),
            ("last_modified_by", "lastModifiedBy"),
            ("title", "title"),
        ):
            value = getattr(properties, attribute)
            masked, count = _redact_labeled_value(label, value or "", args)
            if count:
                setattr(properties, attribute, masked)
                redacted_matches += count

        workbook.save(str(destination))
    finally:
        values_wb.close()
        workbook.close()
    return redacted_matches


def create_redacted_copy(source: Path, destination: Path, args) -> int:
    """Write a separate copy with detected characters replaced by X."""
    source = source.resolve()
    destination = destination.resolve()
    if source == destination:
        raise ValueError("The redacted copy must not overwrite the original file.")
    if destination.exists() and source.samefile(destination):
        raise ValueError("The redacted copy must not overwrite the original file.")
    if source.suffix.lower() != destination.suffix.lower():
        raise ValueError("The redacted copy must use the same file extension as the original.")
    if not source.is_file():
        raise FileNotFoundError(f"Source file not found: {source}")
    if not destination.parent.is_dir():
        raise FileNotFoundError(f"Output folder not found: {destination.parent}")

    redactors = {
        ".pdf": _redact_pdf,
        ".docx": _redact_docx,
        ".xlsx": _redact_xlsx,
    }
    redactor = redactors.get(source.suffix.lower())
    if redactor is None:
        raise ValueError("Redacted copies are supported only for PDF, DOCX, and XLSX files.")

    fd, temporary_name = tempfile.mkstemp(
        prefix=".redacted_", suffix=destination.suffix, dir=destination.parent)
    os.close(fd)
    temporary_path = Path(temporary_name)
    try:
        redacted_units = redactor(source, temporary_path, args)
        os.replace(temporary_path, destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return redacted_units


def _page_summary_rowheight(table_height: int) -> int:
    return max(48, min(144, table_height - 40))


def file_risk(r: dict) -> str:
    """Risk label for the summary. A file that errored out before any result is NOT 'clean'."""
    if r["error"] and not r["findings"]:
        return "NOT SCANNED"
    return risk_level(r["findings"])


def risk_level(findings: list[dict]) -> str:
    cats_high = {"US SSN", "Payment card number", "IBAN"}
    if any(f["category"] in cats_high and f["confidence"] == "high" for f in findings):
        return "HIGH"
    if any(f["confidence"] in ("high", "medium") for f in findings):
        return "MEDIUM"
    return "LOW" if findings else "NONE FOUND"


def create_scan_output_dir(source: Path) -> Path:
    safe_stem = re.sub(
        r'[<>:"/\\|?*\x00-\x1f]', "_", source.stem
    ).strip(" .")
    safe_stem = (safe_stem or "scanned_file")[:80]
    base_name = f"{time.strftime('%Y%m%d_%H%M%S')}_{safe_stem}"
    for suffix in range(1000):
        folder_name = base_name if suffix == 0 else f"{base_name}_{suffix + 1}"
        candidate = source.parent / folder_name
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise FileExistsError(
        f"Could not create a unique output folder beside {source}.")


# ----------------------------------------------------------------- reporting
CSS = """body{font-family:system-ui,Segoe UI,Arial;margin:2rem;color:#222}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}
th,td{border:1px solid #ccc;padding:.35rem .5rem;font-size:.9rem;text-align:left;vertical-align:top}
th{background:#f3f3f3}.HIGH{color:#b00020;font-weight:700}.MEDIUM{color:#b26a00;font-weight:700}
.LOW{color:#555}.summary{white-space:pre-line}.warn{background:#fff4e5;border:1px solid #f0c36d;padding:.6rem;margin-bottom:1rem}
code{background:#f6f6f6;padding:0 .2rem}"""


def write_reports(results: list[dict], outdir: Path, args):
    outdir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d_%H%M%S")
    (outdir / f"scan_{stamp}.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    h = [f"<html><head><meta charset='utf-8'><title>{TOOL_NAME}</title><style>{CSS}</style></head><body>",
         f"<h1>{TOOL_NAME}</h1>", f"<div class='warn'><b>{html.escape(BANNER)}</b></div>",
         f"<p>Generated {time.strftime('%Y-%m-%d %H:%M:%S')} &middot; layers: rules + "
         f"Ollama ({html.escape(args.model)}){' + NER' if args.ner else ''}</p>",
         "<div class='warn'>This report lists <b>candidates</b> for human review. It can miss items and can "
         "contain false alarms. Values are masked by default. If email preservation is enabled, email "
         "addresses remain visible in findings, summaries, and reports. The report is still sensitive: store and share it "
         "accordingly. Findings from the language model alone are shown as low confidence and carry a "
         "short evidence phrase copied from the page.</div>",
         "<h2>Summary</h2><table><tr><th>File</th><th>Pages scanned</th><th>Findings</th><th>Risk</th><th>Status</th></tr>"]
    for r in results:
        rl = file_risk(r)
        status = html.escape(r["error"]) if r["error"] else "scanned"
        cls = "HIGH" if rl in ("HIGH", "NOT SCANNED") else "MEDIUM" if rl == "MEDIUM" else "LOW"
        h.append(f"<tr><td>{html.escape(r['file'])}</td><td>{r['pages_scanned']}</td>"
                 f"<td>{len(r['findings'])}</td><td class='{cls}'>{rl}</td><td>{status}</td></tr>")
    h.append("</table>")
    for r in results:
        h.append(f"<h2>{html.escape(r['file'])}</h2>")
        h.append(f"<p>sha256 <code>{r['sha256'][:16]}…</code> &middot; {r['pages_scanned']} page(s) in {r['seconds']}s")
        if r["error"]:
            h.append(f" &middot; <b>{html.escape(r['error'])}</b>")
        h.append("</p>")
        coverage_warnings = r.get("coverage_warnings", [])
        if coverage_warnings:
            h.append("<h3>Coverage warnings</h3><ul>")
            h.extend(
                f"<li>{html.escape(warning)}</li>"
                for warning in coverage_warnings
            )
            h.append("</ul>")
        document_summary = r.get("document_summary")
        document_summary_error = r.get("document_summary_error")
        if document_summary:
            h.append("<h3>Document overview</h3>")
            h.append(
                f"<p>{html.escape(document_summary['description'])}</p>")
            if document_summary["main_points"]:
                h.append("<ol>")
                h.extend(
                    f"<li>{html.escape(point)}</li>"
                    for point in document_summary["main_points"][:3]
                )
                h.append("</ol>")
        elif document_summary_error:
            h.append(
                "<h3>Document overview unavailable</h3>"
                f"<p>{html.escape(document_summary_error)}</p>")
        if r["page_summaries"]:
            findings_by_page = {}
            for finding in r["findings"]:
                findings_by_page.setdefault(finding["page"], []).append(finding)
            h.append(
                "<table><tr><th>Page</th><th>Page summary</th>"
                "<th>Category</th><th>Masked value</th><th>Source</th>"
                "<th>Confidence</th><th>Context analysis</th><th>Context</th></tr>")
            for page_summary in r["page_summaries"]:
                page_number = page_summary["page"]
                page_findings = findings_by_page.get(page_number, [])
                if not page_findings:
                    page_findings = [{
                        "category": "No findings",
                        "masked": "",
                        "source": "",
                        "confidence": "",
                        "context": "",
                    }]
                for finding in page_findings:
                    h.append(
                        f"<tr><td>{page_number}</td>"
                        f"<td class='summary'>{html.escape(page_summary['summary'])}</td>"
                        f"<td>{html.escape(finding['category'])}</td>"
                        f"<td><code>{html.escape(finding['masked'])}</code></td>"
                        f"<td>{html.escape(finding['source'])}</td>"
                        f"<td>{html.escape(finding['confidence'])}</td>"
                        f"<td>{html.escape(page_summary.get('context_analysis', 'Unknown'))}</td>"
                        f"<td>{html.escape(finding['context'])}</td></tr>")
            h.append("</table>")
        elif r["findings"]:
            h.append("<p>Page summaries unavailable.</p>")
        elif not r["error"]:
            h.append("<p>No findings.</p>")
        if r["pages_scanned"]:
            cp = r["clean_pages"]
            h.append(f"<p>Pages with no findings: {len(cp)} of {r['pages_scanned']}.</p>")
    h.append("</body></html>")
    path = outdir / f"scan_{stamp}.html"
    path.write_text("\n".join(h), encoding="utf-8")
    return path


# ----------------------------------------------------------------- main
def collect(paths: list[str]) -> list[Path]:
    files = []
    for p in paths:
        pp = Path(p)
        if pp.is_dir():
            for f in sorted(pp.rglob("*")):
                if f.is_file() and not f.is_symlink() and f.suffix.lower() in SUPPORTED | REFUSED | REPORT_UNSUPPORTED:
                    files.append(f)
        elif pp.is_file():
            files.append(pp)
        else:
            print(f"[warn] not found: {p}", file=sys.stderr)
    return files


def launch_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from types import SimpleNamespace

    class ScannerApp(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title(TOOL_NAME)
            self.geometry("1450x780")
            self.minsize(1000, 600)
            self.selected_path = None
            self.events = queue.Queue()
            self.scan_args = None
            self.result = None
            self.output_dir = None
            self.pages_scanned = 0
            self.finding_count = 0
            self.scan_running = False
            self.protocol("WM_DELETE_WINDOW", self._on_close)

            self.configure(background="#f3f6fb")
            style = ttk.Style(self)
            if "clam" in style.theme_names():
                style.theme_use("clam")
            style.configure(".", font=("Segoe UI", 10))
            style.configure("App.TFrame", background="#f3f6fb")
            style.configure("Card.TFrame", background="#ffffff")
            style.configure(
                "Card.TLabelframe",
                background="#ffffff",
                bordercolor="#dce3ed",
                relief="solid",
                padding=12,
            )
            style.configure(
                "Card.TLabelframe.Label",
                background="#ffffff",
                foreground="#23344d",
                font=("Segoe UI", 10, "bold"),
            )
            style.configure(
                "Title.TLabel",
                background="#f3f6fb",
                foreground="#15243a",
                font=("Segoe UI", 20, "bold"),
            )
            style.configure(
                "Subtitle.TLabel",
                background="#f3f6fb",
                foreground="#58677c",
            )
            style.configure(
                "Path.TLabel",
                background="#ffffff",
                foreground="#34445a",
                padding=(10, 8),
            )
            style.configure(
                "TCheckbutton",
                background="#ffffff",
                foreground="#34445a",
                padding=(2, 4),
            )
            style.map(
                "TCheckbutton",
                background=[("active", "#ffffff")],
                foreground=[("disabled", "#8a96a5")],
            )
            style.configure(
                "TEntry",
                padding=(7, 6),
                fieldbackground="#ffffff",
                foreground="#26364a",
                bordercolor="#cbd5e1",
            )
            style.configure(
                "Info.TLabel",
                background="#eaf2fc",
                foreground="#294b73",
                padding=10,
            )
            style.configure(
                "Status.TFrame",
                background="#eaf2fc",
            )
            style.configure(
                "Status.TLabel",
                background="#eaf2fc",
                foreground="#294b73",
            )
            style.configure(
                "TButton",
                padding=(12, 7),
                background="#e8edf4",
                foreground="#23344d",
                bordercolor="#d4dce7",
            )
            style.map(
                "TButton",
                background=[("active", "#dce5f0"), ("disabled", "#edf0f4")],
                foreground=[("disabled", "#8a96a5")],
            )
            style.configure(
                "Accent.TButton",
                background="#1769aa",
                foreground="#ffffff",
                bordercolor="#1769aa",
                font=("Segoe UI", 10, "bold"),
            )
            style.map(
                "Accent.TButton",
                background=[("active", "#12578f"), ("disabled", "#a9bfd2")],
                foreground=[("disabled", "#f4f7fa")],
            )
            style.configure(
                "Treeview",
                background="#ffffff",
                fieldbackground="#ffffff",
                foreground="#26364a",
                rowheight=144,
                bordercolor="#dce3ed",
                font=("Segoe UI", 9),
            )
            style.configure(
                "Treeview.Heading",
                background="#eaf0f7",
                foreground="#26364a",
                padding=(7, 8),
                font=("Segoe UI", 9, "bold"),
            )
            style.map(
                "Treeview.Heading",
                background=[("active", "#dce6f1")],
            )
            style.configure(
                "Accent.Horizontal.TProgressbar",
                background="#1769aa",
                troughcolor="#e2e8f0",
                bordercolor="#e2e8f0",
                lightcolor="#1769aa",
                darkcolor="#1769aa",
            )
            style.map(
                "Treeview",
                background=[("selected", "#cfe3f7")],
                foreground=[("selected", "#15243a")],
            )

            status_row = ttk.Frame(
                self, style="Status.TFrame", padding=(10, 5), relief="solid",
                borderwidth=1,
            )
            self.status_bar = status_row
            status_row.pack(
                side="bottom", fill="x", padx=14, pady=(0, 8))
            self.status_var = tk.StringVar(value="Ready - choose a document to scan.")
            ttk.Label(
                status_row, text="SCAN STATUS",
                style="Status.TLabel", font=("Segoe UI", 9, "bold"),
            ).pack(side="left", padx=(0, 10))
            ttk.Label(
                status_row, textvariable=self.status_var,
                style="Status.TLabel",
            ).pack(side="left", fill="x", expand=True)
            self.progress_label_var = tk.StringVar(value="Ready")
            ttk.Label(
                status_row, textvariable=self.progress_label_var,
                style="Status.TLabel",
                font=("Segoe UI", 9, "bold"),
            ).pack(side="right", padx=(12, 8))
            self.progress = ttk.Progressbar(
                status_row, mode="indeterminate", length=240,
                style="Accent.Horizontal.TProgressbar")
            self.progress.pack(side="right", padx=(4, 0))

            main = ttk.Frame(self, padding=14, style="App.TFrame")
            main.pack(fill="both", expand=True)
            ttk.Label(main, text=TOOL_NAME, style="Title.TLabel").pack(anchor="w")
            ttk.Label(
                main,
                text="Local document screening for PDF, DOCX, and XLSX files.",
                style="Subtitle.TLabel",
                wraplength=1000,
            ).pack(anchor="w", pady=(2, 8))

            self.main_content = ttk.Frame(main, style="App.TFrame", padding=(0, 0, 0, 4))
            self.main_content.pack(fill="both", expand=True)

            document_cards = ttk.Frame(self.main_content, style="App.TFrame")
            self.document_cards = document_cards
            document_cards.pack(fill="x", pady=(0, 6))
            document_cards.columnconfigure(0, weight=1, uniform="document_cards")
            document_cards.columnconfigure(1, weight=2, uniform="document_cards")
            file_section = ttk.LabelFrame(
                document_cards, text="Document", style="Card.TLabelframe",
                height=112)
            self.document_card = file_section
            file_section.grid(row=0, column=0, sticky="new", padx=(0, 4))
            file_section.grid_propagate(False)
            file_row = ttk.Frame(file_section, style="Card.TFrame")
            file_row.pack(fill="x", pady=(5, 4))
            self.scan_button = ttk.Button(
                file_row, text="Scan document", command=self._start_scan,
                state="disabled", style="Accent.TButton")
            self.scan_button.pack(side="left", padx=(0, 8))
            self.choose_button = ttk.Button(
                file_row, text="Choose file...", command=self._choose_file)
            self.choose_button.pack(side="left")
            path_row = ttk.Frame(file_section, style="Card.TFrame")
            path_row.pack(fill="x")
            self.path_var = tk.StringVar(value="No file selected")
            ttk.Label(
                path_row,
                textvariable=self.path_var,
                style="Path.TLabel",
                anchor="w",
            ).pack(fill="x", expand=True)

            summary_frame = ttk.LabelFrame(
                self.main_content, text="Document overview", style="Card.TLabelframe",
                height=96,
            )
            self.document_overview_card = summary_frame
            summary_frame.pack(fill="x", pady=(0, 5))
            summary_frame.pack_propagate(False)

            category_frame = ttk.LabelFrame(
                document_cards, text="Detection options",
                style="Card.TLabelframe", height=150)
            self.detection_options_frame = category_frame
            category_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
            category_frame.grid_propagate(False)
            for column in range(4):
                category_frame.columnconfigure(column, weight=1)
            self.ner_var = tk.BooleanVar(value=False)
            self.ner_checkbutton = ttk.Checkbutton(
                category_frame,
                text="Named Entity Recognition (NER)",
                variable=self.ner_var,
            )
            self.ner_checkbutton.grid(row=0, column=0, sticky="w", pady=1)
            self.detect_emails_var = tk.BooleanVar(value=True)
            self.detect_emails_checkbutton = ttk.Checkbutton(
                category_frame,
                text="Email addresses",
                variable=self.detect_emails_var,
            )
            self.detect_emails_checkbutton.grid(
                row=0, column=1, sticky="w", pady=1)
            self.analyze_all_var = tk.BooleanVar(value=False)
            self.analyze_all_checkbutton = ttk.Checkbutton(
                category_frame,
                text="Context findings on every page (slower)",
                variable=self.analyze_all_var,
            )
            self.analyze_all_checkbutton.grid(
                row=0, column=2, columnspan=2, sticky="w", pady=1)
            self.category_vars = {}
            for index, (category_id, label) in enumerate(SENSITIVE_CATEGORIES):
                variable = tk.BooleanVar(value=True)
                self.category_vars[category_id] = variable
                ttk.Checkbutton(
                    category_frame,
                    text=label,
                    variable=variable,
                ).grid(
                    row=1 + index // 4, column=index % 4, sticky="w",
                    padx=(0, 10), pady=1)
            dashboard = ttk.Frame(self.main_content, style="App.TFrame")
            dashboard.pack(fill="both", expand=True)
            table_frame = ttk.Frame(dashboard, style="Card.TFrame", padding=5)
            table_frame.pack(fill="both", expand=True)
            self.document_summary_text = tk.Text(
                summary_frame, wrap="word", width=28, height=5,
                state="disabled", padx=12, pady=10,
                background="#ffffff", foreground="#26364a",
                font=("Segoe UI", 10), relief="flat", borderwidth=0,
                highlightthickness=1, highlightbackground="#dce3ed",
                highlightcolor="#1769aa",
            )
            summary_scrollbar = ttk.Scrollbar(
                summary_frame, orient="vertical",
                command=self.document_summary_text.yview,
            )
            self.document_summary_text.configure(
                yscrollcommand=summary_scrollbar.set)
            self.document_summary_text.pack(
                side="left", fill="both", expand=True)
            summary_scrollbar.pack(side="right", fill="y")
            columns = (
                "page", "summary", "category", "value", "source", "confidence",
                "context_analysis")
            self.table = ttk.Treeview(
                table_frame, columns=columns, show="headings", height=3,
                style="PageSummary.Treeview")
            style.configure("PageSummary.Treeview", rowheight=72)
            self.table.bind(
                "<Configure>",
                lambda event: style.configure(
                    "PageSummary.Treeview",
                    rowheight=_page_summary_rowheight(event.height),
                ),
                add="+",
            )
            self.table.tag_configure("row_even", background="#ffffff")
            self.table.tag_configure("row_odd", background="#f5f8fc")
            self.table.tag_configure(
                "no_findings", foreground="#68778a", background="#f5f8fc")
            headings = {
                "page": ("Page", 48),
                "summary": ("Page summary", 680),
                "category": ("Category / detected text", 200),
                "value": ("Masked value", 110),
                "source": ("Source", 70),
                "confidence": ("Confidence", 90),
                "context_analysis": ("Context check", 100),
            }
            for name, (label, width) in headings.items():
                self.table.heading(name, text=label)
                self.table.column(
                    name,
                    width=width,
                    minwidth=(
                        48 if name == "page"
                        else 420 if name == "summary"
                        else 70 if name in {"source", "confidence"}
                        else 95 if name == "context_analysis"
                        else 90
                    ),
                    stretch=name == "summary",
                    anchor="w",
                )
            table_frame.rowconfigure(0, weight=1)
            table_frame.columnconfigure(0, weight=1)
            scrollbar = ttk.Scrollbar(
                table_frame, orient="vertical", command=self.table.yview)
            horizontal_scrollbar = ttk.Scrollbar(
                table_frame, orient="horizontal", command=self.table.xview)
            self.table.configure(
                yscrollcommand=scrollbar.set,
                xscrollcommand=horizontal_scrollbar.set,
            )
            self.table.grid(row=0, column=0, sticky="nsew")
            scrollbar.grid(row=0, column=1, sticky="ns")
            horizontal_scrollbar.grid(row=1, column=0, sticky="ew")

        def _choose_file(self):
            path = filedialog.askopenfilename(
                title="Choose a document to scan",
                filetypes=[
                    ("Scannable documents", "*.pdf *.docx *.xlsx"),
                    ("All files", "*.*"),
                ],
            )
            if path:
                self.selected_path = Path(path)
                self.path_var.set(str(self.selected_path))
                self.scan_button.configure(state="normal")
                self.status_var.set("Ready to scan")

        def _start_scan(self):
            if self.scan_running:
                return
            if not self.selected_path or not self.selected_path.is_file():
                messagebox.showerror("File not found", "Choose an existing file to scan.")
                return

            self.table.delete(*self.table.get_children())
            self._set_document_summary("The document overview will appear after scanning.")
            self.pages_scanned = 0
            self.finding_count = 0
            self.displayed_pages = set()
            self.result = None
            self.output_dir = None
            self.scan_args = SimpleNamespace(
                ner=self.ner_var.get(),
                keep_emails=False,
                ignore_emails=not self.detect_emails_var.get(),
                disabled_categories=[
                    category_id
                    for category_id, variable in self.category_vars.items()
                    if not variable.get()
                ],
                llm=True,
                llm_all=self.analyze_all_var.get(),
                model="qwen3:4b",
                host="http://127.0.0.1:11434",
                llm_timeout=120,
                verbose=False,
            )
            if self.scan_args.llm and not is_local_ollama_host(self.scan_args.host):
                messagebox.showerror(
                    "Invalid Ollama host", "Only a local Ollama service is allowed.")
                return

            self.choose_button.configure(state="disabled")
            self.scan_button.configure(state="disabled")
            self.scan_running = True
            self.progress.start(12)
            self.status_var.set(
                f"Preparing to scan {self.selected_path.name}...")
            self.progress_label_var.set("Starting")
            worker = threading.Thread(target=self._scan_worker, daemon=True)
            worker.start()
            self.after(100, self._process_events)

        def _on_close(self):
            if self.scan_running:
                messagebox.showwarning(
                    "Analysis in progress",
                    "Please wait for the current scan to finish before closing the application.",
                )
                return
            self.destroy()

        def _scan_worker(self):
            path = self.selected_path
            started = time.time()
            result = {
                "file": path.name,
                "sha256": "",
                "pages_scanned": 0,
                "findings": [],
                "page_summaries": [],
                "document_summary": None,
                "document_summary_error": None,
                "clean_pages": [],
                "coverage_warnings": [],
                "error": None,
                "seconds": 0,
            }
            work = None
            try:
                ensure_ollama_available(
                    self.scan_args.host,
                    self.scan_args.model,
                    self.scan_args.llm_timeout,
                )
                work = Path(tempfile.mkdtemp(prefix="scan_"))
                os.chmod(work, 0o700)
                local = work / f"{hashlib.md5(str(path).encode()).hexdigest()[:8]}{path.suffix.lower()}"
                shutil.copyfile(path, local)
                result = scan_file(
                    local,
                    self.scan_args,
                    on_page=lambda page, findings, summary, context_analysis: self.events.put(
                        ("page", page, findings, summary, context_analysis),
                    ),
                )
                result["file"] = path.name
            except Exception as exc:
                result["error"] = f"{type(exc).__name__}: {exc}"
                result["seconds"] = round(time.time() - started, 1)
            finally:
                if work is not None:
                    shutil.rmtree(work, ignore_errors=True)
            self.events.put(("done", result))

        def _process_events(self):
            try:
                while True:
                    event = self.events.get_nowait()
                    if event[0] == "page":
                        _, page, findings, summary, context_analysis = event
                        self.pages_scanned += 1
                        self._display_page_rows(
                            page, findings, summary, context_analysis)
                        self.finding_count += len(findings)
                        self.status_var.set(
                            f"Scanning - {self.pages_scanned} page/chunk(s) completed; "
                            f"{self.finding_count} finding(s) found "
                            f"(latest: {page})."
                        )
                        self.progress_label_var.set(
                            f"Page {page} complete")
                    elif event[0] == "done":
                        self._finish_scan(event[1])
                        return
            except queue.Empty:
                self.after(100, self._process_events)

        def _display_page_rows(
            self, page: int, findings: list[dict], summary: str,
            context_analysis: str = "Unknown",
        ):
            self.displayed_pages.add(page)
            display_findings = findings or [{
                "page": page,
                "category": "No findings",
                "masked": "",
                "source": "",
                "confidence": "",
            }]
            for finding in display_findings:
                row_tag = (
                    "no_findings"
                    if finding["category"] == "No findings"
                    else "row_even"
                    if len(self.table.get_children()) % 2 == 0
                    else "row_odd"
                )
                self.table.insert(
                    "",
                    "end",
                    values=(
                        finding.get("page", page),
                        summary,
                        (
                            f"{finding['category']}: {finding['detected_text']}"
                            if finding.get("detected_text")
                            else finding["category"]
                        ),
                        finding.get("masked", ""),
                        finding.get("source", ""),
                        finding.get("confidence", ""),
                        context_analysis,
                    ),
                    tags=(row_tag,),
                )

        def _finish_scan(self, result):
            self.progress.stop()
            self.scan_running = False
            self.choose_button.configure(state="normal")
            self.scan_button.configure(state="normal")
            self.result = result
            for page_summary in result.get("page_summaries", []):
                page = page_summary["page"]
                if page in self.displayed_pages:
                    continue
                page_findings = [
                    finding for finding in result.get("findings", [])
                    if finding["page"] == page
                ]
                self._display_page_rows(
                    page, page_findings, page_summary["summary"],
                    page_summary.get("context_analysis", "Unknown"))
            self.pages_scanned = max(
                self.pages_scanned, result.get("pages_scanned", 0))
            self.finding_count = max(
                self.finding_count, len(result.get("findings", [])))
            if result.get("document_summary"):
                overview = result["document_summary"]
                points = overview.get("main_points", [])[:3]
                text = overview.get("description", "")
                if points:
                    text += "\n\nMain points\n" + "\n".join(
                        f"{index}. {point}"
                        for index, point in enumerate(points, 1)
                    )
                self._set_document_summary(text)
            elif result.get("document_summary_error"):
                self._set_document_summary(
                    "Document overview unavailable:\n"
                    + result["document_summary_error"])
            elif result.get("error"):
                self._set_document_summary(
                    "Document overview unavailable because the scan did not complete.")
            else:
                self._set_document_summary("No page summaries are available.")
            if result.get("coverage_warnings"):
                warning_text = "\n".join(
                    f"- {warning}" for warning in result["coverage_warnings"])
                current_summary = self.document_summary_text.get("1.0", "end").strip()
                self._set_document_summary(
                    f"{current_summary}\n\nCoverage warnings\n{warning_text}")
            if result["error"]:
                self.progress_label_var.set("Stopped")
                self.status_var.set(
                    f"Scan finished with an error after {result['pages_scanned']} page(s).")
                messagebox.showwarning(
                    "Scan completed with an error",
                    f"{result['error']}\n\nAny completed page findings remain visible.",
                )
                self._save_report_and_open_folder()
                return

            self.status_var.set(
                f"Scan complete: {result['pages_scanned']} page(s), "
                f"{len(result['findings'])} finding(s)."
            )
            self.progress_label_var.set("Complete")
            try:
                output_dir = self._ensure_output_dir()
            except OSError as exc:
                messagebox.showerror(
                    "Could not create output folder",
                    f"{type(exc).__name__}: {exc}",
                )
                return

            destination = (
                output_dir
                / f"{self.selected_path.stem}_redacted{self.selected_path.suffix}"
            )
            self._start_redaction(destination)

        def _set_document_summary(self, text: str):
            self.document_summary_text.configure(state="normal")
            self.document_summary_text.delete("1.0", "end")
            self.document_summary_text.insert("1.0", text)
            self.document_summary_text.configure(state="disabled")

        def _ensure_output_dir(self) -> Path:
            if self.output_dir is not None:
                return self.output_dir
            self.output_dir = create_scan_output_dir(self.selected_path)
            return self.output_dir

        def _start_redaction(self, destination: Path):
            self.scan_running = True
            self.choose_button.configure(state="disabled")
            self.scan_button.configure(state="disabled")
            self.progress.start(12)
            self.status_var.set("Creating redacted copy...")
            self.progress_label_var.set("Redacting")

            def worker():
                try:
                    count = create_redacted_copy(
                        self.selected_path, destination, self.scan_args)
                    self.events.put(("redaction_done", (destination, count, None)))
                except Exception as exc:
                    self.events.put(("redaction_done", (destination, 0, exc)))

            threading.Thread(target=worker, daemon=True).start()
            self.after(100, self._process_redaction_events)

        def _process_redaction_events(self):
            try:
                while True:
                    event = self.events.get_nowait()
                    if event[0] != "redaction_done":
                        continue
                    destination, count, error = event[1]
                    self.progress.stop()
                    self.scan_running = False
                    self.choose_button.configure(state="normal")
                    self.scan_button.configure(state="normal")
                    if error:
                        self.status_var.set("Could not create redacted copy.")
                        self.progress_label_var.set("Error")
                        messagebox.showerror(
                            "Redaction failed",
                            f"{type(error).__name__}: {error}",
                        )
                    else:
                        self.status_var.set(
                            f"Redacted copy saved; {count} match(es) replaced with Xs. "
                            "Saving report and opening output folder...")
                        self.progress_label_var.set("Saving report")
                    self._save_report_and_open_folder()
                    return
            except queue.Empty:
                self.after(100, self._process_redaction_events)

        def _save_report_and_open_folder(self):
            try:
                outdir = self._ensure_output_dir()
                report = write_reports([self.result], outdir, self.scan_args)
            except (OSError, UnicodeError) as exc:
                self.status_var.set("Could not save the scan report.")
                self.progress_label_var.set("Error")
                messagebox.showerror(
                    "Could not save report", f"{type(exc).__name__}: {exc}")
            else:
                self.status_var.set(
                    f"Report saved. Opening output folder: {outdir}")
                self.progress_label_var.set("Done")
                try:
                    os.startfile(str(outdir))
                except OSError as exc:
                    messagebox.showerror(
                        "Could not open output folder",
                        f"Report saved at:\n{report}\n\n"
                        f"{type(exc).__name__}: {exc}",
                    )

    ScannerApp().mainloop()


def main():
    ap = argparse.ArgumentParser(description="Detect-and-report sensitive data scanner (PDF/DOCX/XLSX).")
    ap.add_argument("paths", nargs="*", help="files or folders (e.g. a mounted USB drive)")
    ap.add_argument("--gui", action="store_true", help="launch the desktop interface")
    ap.add_argument("-o", "--outdir", default="scan_reports")
    ap.add_argument("--ner", action="store_true", help="enable Presidio NER layer")
    email_options = ap.add_mutually_exclusive_group()
    email_options.add_argument(
        "--keep-emails",
        action="store_true",
        help="detect emails but leave them unmasked in findings, summaries, reports, and redacted copies",
    )
    email_options.add_argument(
        "--ignore-emails",
        action="store_true",
        help="do not detect email addresses or include them as findings",
    )
    ap.add_argument(
        "--disable-category",
        dest="disabled_categories",
        action="append",
        choices=sorted(SENSITIVE_CATEGORY_IDS | LEGACY_CATEGORY_ALIASES.keys()),
        metavar="CATEGORY",
        help=(
            "skip detection and masking for this category; repeat as needed. "
            "Choices: " + ", ".join(sorted(
                SENSITIVE_CATEGORY_IDS | LEGACY_CATEGORY_ALIASES.keys()))
        ),
    )
    ap.add_argument("--llm", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--llm-all", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--deep", action="store_true",
                    help="ask the model for contextual findings on EVERY page (slower, more false alerts)")
    ap.add_argument("--model", default="qwen3:4b")
    ap.add_argument("--host", default="http://127.0.0.1:11434")
    ap.add_argument("--llm-timeout", type=int, default=120)
    ap.add_argument("--keep-copy", action="store_true", help="do not delete the temp working copy")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    if args.gui or not args.paths:
        launch_gui()
        return

    args.llm = True
    args.llm_all = bool(args.deep or args.llm_all)
    try:
        ensure_ollama_available(args.host, args.model, args.llm_timeout)
    except (RuntimeError, ValueError) as exc:
        sys.exit(str(exc))

    print(f"== {TOOL_NAME} ==\n{BANNER}\n", file=sys.stderr)
    files = collect(args.paths)
    if not files:
        sys.exit("No supported files found.")

    work = Path(tempfile.mkdtemp(prefix="scan_"))
    os.chmod(work, 0o700)
    results = []
    try:
        for f in files:
            print(f"Scanning {f.name} ...", file=sys.stderr)
            # work on a copy: the original (e.g. USB) is never opened for writing
            local = work / f"{hashlib.md5(str(f).encode()).hexdigest()[:8]}{f.suffix.lower()}"
            shutil.copyfile(f, local)
            r = scan_file(local, args)
            r["file"] = f.name
            results.append(r)
    finally:
        if not args.keep_copy:
            shutil.rmtree(work, ignore_errors=True)

    rep = write_reports(results, Path(args.outdir), args)
    print(f"\nReport: {rep}")
    for r in results:
        print(f"  {r['file']}: {file_risk(r)}  ({len(r['findings'])} findings"
              f"{', ' + r['error'] if r['error'] else ''})")


if __name__ == "__main__":
    main()
