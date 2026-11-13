"""Domain helpers shared by the sender check, the URL scanner and the link scan.

- Trusted-domain matching includes subdomains (portal.westbrook.edu matches westbrook.edu).
- Generic university-lookalike detection needs no configuration: a host that contains a
  ".edu"/".ac.xx" address without ending in one (westbrook.edu-verify.com, westbrook-edu.com)
  is dressed up as a university.
- Optional campus lookalike detection (only when CAMPUS_DOMAINS is configured) also catches
  typos of that specific domain (westbr0ok.edu) and wrappers (westbrook-login.com).
"""

import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from app import config

# Public suffixes made of two labels that are common for universities and companies.
MULTI_PART_SUFFIXES = {
    "ac.uk", "co.uk", "org.uk", "gov.uk",
    "ac.id", "co.id", "or.id", "go.id", "sch.id", "web.id", "my.id",
    "edu.au", "com.au", "ac.nz", "co.nz", "ac.jp", "co.jp",
    "edu.sg", "com.sg", "edu.my", "com.my", "ac.in", "co.in", "edu.in",
    "edu.cn", "com.cn", "com.br", "edu.br", "ac.za", "co.za",
    "edu.tw", "ac.kr", "edu.hk", "ac.th", "edu.ph", "edu.vn",
}

_SKELETON_MAP = str.maketrans({
    "0": "o", "1": "l", "i": "l", "!": "l", "|": "l", "5": "s", "@": "a", "3": "e", "$": "s",
})

LOGIN_HINTS = (
    "login", "log-in", "logon", "signin", "sign-in", "sso", "auth", "portal", "account",
    "verify", "password", "passwd", "webmail", "mfa", "2fa", "secure", "credential",
)


def normalize_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def skeleton(text: str) -> str:
    """Collapse characters that look alike so 'paypa1' and 'paypal' compare equal."""
    return text.lower().replace("rn", "m").replace("vv", "w").translate(_SKELETON_MAP)


_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def registrable_domain(host: str) -> str:
    host = normalize_host(host)
    if _IPV4.match(host):
        return host
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def main_label(host: str) -> str:
    reg = registrable_domain(host)
    return reg.split(".")[0] if reg else ""


def matches_domain(host: str, domain: str) -> bool:
    host, domain = normalize_host(host), normalize_host(domain)
    return bool(host) and bool(domain) and (host == domain or host.endswith("." + domain))


def find_trusted(host: str, trusted: Dict[str, str]) -> Optional[Tuple[str, str]]:
    """Return (matched_trusted_domain, category) for the most specific match, if any."""
    best: Optional[Tuple[str, str]] = None
    for domain, category in trusted.items():
        if matches_domain(host, domain) and (best is None or len(domain) > len(best[0])):
            best = (domain, category)
    return best


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def campus_lookalike(host: str, campus_domains: Optional[Iterable[str]] = None) -> Optional[str]:
    """Return the campus domain that `host` imitates, or None.

    A host on (or under) an official campus domain is never a lookalike.
    """
    domains: List[str] = list(campus_domains if campus_domains is not None else config.CAMPUS_DOMAINS)
    host = normalize_host(host)
    if not host or any(matches_domain(host, d) for d in domains):
        return None

    host_skeleton = skeleton(host)
    host_main = skeleton(main_label(host))
    for domain in domains:
        label = main_label(domain)
        if len(label) < 4:  # too short to compare safely (e.g. "ui" for ui.ac.id)
            continue
        label_skeleton = skeleton(label)
        if label_skeleton in host_skeleton:
            return domain
        limit = 1 if len(label) <= 6 else 2
        if levenshtein(host_main, label_skeleton) <= limit:
            return domain
    return None


ACADEMIC_SUFFIXES = ("edu",) + tuple(s for s in sorted(MULTI_PART_SUFFIXES) if s.startswith(("ac.", "edu.")))


def is_academic_domain(host: str) -> bool:
    """True for real university-style domains: anything.edu, anything.ac.uk, anything.ac.id, ..."""
    reg = registrable_domain(host)
    return any(reg == s or reg.endswith("." + s) for s in ACADEMIC_SUFFIXES)


# westbrook.edu-verify.com, sso.ui.ac.id.verify-account.com -> pretends to be westbrook.edu / ui.ac.id
# (two-letter names such as ui.ac.id / ub.ac.id are common, so 2+ characters are allowed here)
_FAKE_ACADEMIC_DOTTED = re.compile(r"(?:^|\.)([a-z0-9-]{2,}\.(?:edu|ac\.[a-z]{2}|edu\.[a-z]{2}))(?=[.-])")
# westbrook-edu.com, my-westbrook-edu.net -> pretends to be westbrook.edu (3+ so "my-edu-portal" isn't flagged)
_FAKE_ACADEMIC_DASH_EDU = re.compile(r"(?:^|\.|-)([a-z0-9]{3,})-edu(?=[.-])")
# ui-ac-id.com, siak-ui-ac-id.com, nus-edu-sg.net -> pretends to be ui.ac.id / nus.edu.sg
_FAKE_ACADEMIC_DASHED_SUFFIX = re.compile(r"(?:^|\.|-)([a-z0-9]{2,})-(ac|edu)-([a-z]{2})(?=\.)")


def fake_academic_domain(host: str) -> Optional[str]:
    """Return the university address this host is dressed up as, or None.

    Generic check that needs no knowledge of a particular campus: a domain that *contains* a
    ".edu"/".ac.xx" address but doesn't actually end in one is imitating a university.
    """
    host = normalize_host(host)
    if not host or is_academic_domain(host):
        return None
    match = _FAKE_ACADEMIC_DOTTED.search(host)
    if match:
        return match.group(1)
    match = _FAKE_ACADEMIC_DASHED_SUFFIX.search(host)
    if match:
        return f"{match.group(1)}.{match.group(2)}.{match.group(3)}"
    match = _FAKE_ACADEMIC_DASH_EDU.search(host)
    if match:
        return f"{match.group(1)}.edu"
    return None


# Domains each protected brand really owns. A host on (or under) one of these is never a lookalike,
# even though it contains the brand's name (login.microsoftonline.com, user.github.io, ...).
BRAND_OWNED_DOMAINS: Dict[str, Tuple[str, ...]] = {
    "paypal.com": ("paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"),
    "microsoft.com": ("microsoft.com", "microsoftonline.com", "microsoft365.com", "onmicrosoft.com", "office.com",
                      "office365.com", "live.com", "outlook.com", "sharepoint.com", "msauth.net", "msftauth.net",
                      "azure.com", "windows.net"),
    "google.com": ("google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "googlemail.com",
                   "gmail.com", "youtube.com", "goo.gl", "g.co", "forms.gle"),
    "github.com": ("github.com", "github.io", "githubusercontent.com", "githubassets.com", "githubapp.com"),
    "stripe.com": ("stripe.com", "stripe.network", "stripe.dev"),
}
BRAND_NAMES: Dict[str, str] = {
    "paypal.com": "PayPal", "microsoft.com": "Microsoft", "google.com": "Google",
    "github.com": "GitHub", "stripe.com": "Stripe",
}


def is_brand_owned(host: str) -> bool:
    return any(matches_domain(host, d) for owned in BRAND_OWNED_DOMAINS.values() for d in owned)


def _is_country_suffix(suffix: str) -> bool:
    return (len(suffix) == 2 and suffix.isalpha()) or suffix in MULTI_PART_SUFFIXES


def brand_lookalike(host: str, brand_keywords: Dict[str, str]) -> Optional[str]:
    """Return the brand domain `host` imitates (e.g. "paypal.com"), or None.

    A brand name counts only as a whole word in the address (paypal-secure, paypalsecurity,
    accounts.google.com.evil.com), compared after folding look-alike characters (paypa1, rnicrosoft).
    It does not count inside an unrelated word (pinstripes), on a domain the brand owns
    (microsoftonline.com, github.io), or on the brand's own country domain (google.co.id).
    """
    host = normalize_host(host)
    if not host or _IPV4.match(host) or is_brand_owned(host):
        return None
    reg = registrable_domain(host)
    main = main_label(host)
    suffix = reg[len(main) + 1:]
    tokens = [t for label in host.split(".") for t in re.split(r"[-_]", label) if t]
    host_skeleton = skeleton(host)

    for keyword, canonical in brand_keywords.items():
        if matches_domain(host, canonical):
            return None
        if main == main_label(canonical) and _is_country_suffix(suffix):
            continue  # the brand's own regional site, e.g. google.co.id
        kw = skeleton(keyword)
        if "-" in keyword or "." in keyword:  # multi-word keyword such as "acme-corp"
            if kw in host_skeleton:
                return canonical
            continue
        for token in tokens:
            ts = skeleton(token)
            if ts == kw or (len(ts) - len(kw) >= 3 and (ts.startswith(kw) or ts.endswith(kw))):
                return canonical
    return None


def university_lookalike(host: str) -> Optional[str]:
    """Configured campus lookalike first (if any campus is configured), then the generic checks."""
    return campus_lookalike(host) or fake_academic_domain(host) or academic_typo(host)


def is_login_like(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    haystack = f"{parsed.hostname or ''} {parsed.path or ''} {parsed.query or ''}".lower()
    return any(hint in haystack for hint in LOGIN_HINTS)


_BARE_DOMAIN_RE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)


def domains_in_text(text: str) -> List[str]:
    """Find things that look like domains in visible text, e.g. anchor text 'www.paypal.com/login'."""
    return [normalize_host(m.group(1)) for m in _BARE_DOMAIN_RE.finditer(text or "")]


# ---------------------------------------------------------------- free webmail providers
# Anyone can open one of these, so a passing DMARC only proves "sent via Gmail", not who the sender is.
FREE_WEBMAIL_LABELS = {
    "gmail", "googlemail", "yahoo", "ymail", "rocketmail", "outlook", "hotmail", "icloud", "aol", "protonmail",
    "proton", "gmx", "yandex", "zoho", "naver", "daum", "hanmail", "rediffmail", "fastmail", "tutanota", "tuta",
}
FREE_WEBMAIL_EXACT = {"live.com", "msn.com", "me.com", "pm.me", "mail.com", "mail.ru", "163.com", "126.com", "qq.com",
                      "web.de", "t-online.de", "inbox.com", "mailbox.org", "seznam.cz", "libero.it"}


def is_free_webmail(domain: str) -> bool:
    reg = registrable_domain(domain)
    return bool(reg) and (reg in FREE_WEBMAIL_EXACT or main_label(reg) in FREE_WEBMAIL_LABELS)


# ---------------------------------------------------------------- link shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "buff.ly",
    "tiny.cc", "shorturl.at", "rebrand.ly", "t.ly", "s.id", "lnkd.in", "tr.im", "bl.ink", "short.io", "qrco.de",
    "snip.ly", "shorte.st", "adf.ly", "v.gd", "clck.ru", "u.to", "x.co", "gg.gg", "soo.gd", "tinyurl.one",
    "hyperurl.co", "1url.com", "shorturl.com", "urlz.fr", "cli.re", "kutt.it", "dub.sh",
}


def is_shortener(host: str) -> bool:
    host = normalize_host(host)
    return bool(host) and (host in SHORTENER_DOMAINS or registrable_domain(host) in SHORTENER_DOMAINS)


# ---------------------------------------------------------------- domains built from "security words"
# Phishing sites are very often named after the thing they imitate: webmail-upgrade-center.com,
# drive-docs-shared.com, wallet-verify-center.com. Real organisations are named after themselves.
SECURITY_WORDS = {
    "secure", "security", "verify", "verification", "verified", "login", "logon", "signin", "auth", "authenticate",
    "authentication", "password", "passwd", "confirm", "confirmation", "validate", "validation", "update", "updates",
    "unlock", "recover", "recovery", "reactivate", "activate", "activation", "suspended", "alert", "alerts", "notice",
    "notification", "notifications", "support", "helpdesk", "service", "services", "center", "centre", "portal",
    "account", "accounts", "billing", "invoice", "invoices", "payment", "payments", "refund", "refunds", "wallet",
    "reward", "rewards", "prize", "claim", "bonus", "release", "upgrade", "award", "grant", "grants", "scholarship",
    "deposit", "fee", "fees", "free", "urgent", "official",
}
SERVICE_WORDS = {
    "mail", "webmail", "mailbox", "email", "inbox", "docs", "doc", "drive", "share", "shared", "sharing", "file",
    "files", "cloud", "storage", "office", "office365", "o365", "outlook", "onedrive", "sharepoint", "dropbox",
    "docusign", "sso", "mfa", "2fa", "exec", "admin", "student", "students", "uni", "campus", "faculty", "staff",
    "hr", "payroll", "it", "university", "college", "forms",
}


# University departments. Used only next to a university's own name (ntpu-housing.com, cedarridge-exams.top):
# "<university>-<department>" on a domain the university doesn't own is how fake campus offices are named.
# Not used on their own, so an ordinary "campus-housing.org" is not flagged.
CAMPUS_DEPARTMENT_WORDS = {
    "housing", "dorm", "dorms", "residence", "registrar", "registry", "admission", "admissions", "bursar", "finance",
    "financial", "finaid", "tuition", "exam", "exams", "examination", "examinations", "grades", "grade",
    "enrollment", "enrolment", "records", "academic", "academics", "scholarships", "studentaid", "aid",
}


def campus_department_words(host: str) -> List[str]:
    host = normalize_host(host)
    if not host or _IPV4.match(host) or is_academic_domain(host):
        return []
    return [t for t in main_label(host).split("-") if t in CAMPUS_DEPARTMENT_WORDS]


def domain_lure_words(host: str) -> Tuple[List[str], List[str]]:
    """(security words, service words) found in the registrable domain's main label, split on hyphens."""
    host = normalize_host(host)
    if not host or _IPV4.match(host) or is_academic_domain(host) or is_brand_owned(host):
        return [], []
    tokens = [t for t in main_label(host).split("-") if t]
    sec = [t for t in tokens if t in SECURITY_WORDS]
    svc = [t for t in tokens if t in SERVICE_WORDS]
    return sec, svc


def lure_domain_strength(host: str) -> Tuple[str, List[str]]:
    """'strong' (two or more lure words, or a security word next to a service word), 'weak' (one security
    word), or '' -- with the words that matched."""
    sec, svc = domain_lure_words(host)
    words = list(dict.fromkeys(sec + svc))
    if len(sec) >= 2 or (sec and svc) or len(svc) >= 2:
        return "strong", words
    if len(sec) == 1:
        return "weak", words
    return "", words


_DIGIT_FOLD = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s"})


# ---------------------------------------------------------------- academic domain with a digit in place of a letter
# westbr0ok.edu, harr0wgate.ac.uk, 1akesidetech.edu: the suffix is real, the name has a homoglyph digit in it.
def academic_typo(host: str) -> Optional[str]:
    host = normalize_host(host)
    if not host or not is_academic_domain(host):
        return None
    reg = registrable_domain(host)
    label = main_label(reg)
    if not re.fullmatch(r"[a-z0-9]+", label) or not re.search(r"[a-z][0135]|[0135][a-z]", label):
        return None
    if re.search(r"\d{2,}", label) or re.search(r"[a-z]\d+$", label):  # cs50, web3: a numeric suffix, not a swap
        return None
    folded = label.translate(_DIGIT_FOLD)
    if folded == label or not folded.isalpha():
        return None
    return folded + reg[len(label):]


# ---------------------------------------------------------------- lookalikes of domains on the trusted list
def trusted_lookalike(host: str, trusted: Dict[str, str]) -> Optional[str]:
    """Return the trusted domain `host` imitates, or None.

    - the whole domain equal after folding look-alike characters (ntpu.edu.tvv -> ntpu.edu.tw)
    - a one-letter typo of a long name (harvrad.edu -> harvard.edu; names of 7+ letters only)
    - the trusted name as a whole word next to a security/service word (ntpu-login.com, sso-ntpu.net)
    A host on a trusted domain is never a lookalike.
    """
    host = normalize_host(host)
    if not host or _IPV4.match(host) or find_trusted(host, trusted):
        return None
    reg = registrable_domain(host)
    host_sk, reg_sk = skeleton(host), skeleton(reg)
    main_sk = skeleton(main_label(reg))
    tokens = [t for label in host.split(".") for t in label.split("-") if t]
    sec, svc = domain_lure_words(host)
    dept = campus_department_words(host)
    for domain in trusted:
        domain = normalize_host(domain)
        label = main_label(domain)
        if len(label) < 3:
            continue
        domain_sk = skeleton(domain)
        if reg_sk == domain_sk or host_sk == domain_sk:
            return domain
        # The name glued to "edu" (ntpuedu.tw, edu-ntpu.com): no real organisation is called that.
        if is_academic_domain(domain) and main_sk in (skeleton(label + "edu"), skeleton("edu" + label), skeleton("edu-" + label)):
            return domain
        label_sk = skeleton(label)
        if len(label) >= 7 and main_label(reg) != label and _one_typo_away(main_sk, label_sk):
            return domain
        if len(label) >= 4 and (sec or svc or dept) and any(skeleton(t) == label_sk for t in tokens):
            return domain
        if len(label) == 3 and sec and any(t == label for t in tokens):
            return domain
    return None


def _one_typo_away(a: str, b: str) -> bool:
    """One letter added, dropped, changed, or two neighbours swapped (harvrad -> harvard)."""
    if levenshtein(a, b) <= 1:
        return True
    if len(a) == len(b):
        diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    return False


def recipient_lookalike(host: str, recipient_address_or_domain: str) -> Optional[str]:
    """The recipient's address says which university they belong to. A sender or link that carries that
    university's name on another domain (harrowgate-it.help for a @harrowgate.ac.uk student) is imitating it.
    Needs no configuration. Returns the university domain, or None.
    """
    rec = registrable_domain((recipient_address_or_domain or "").split("@")[-1])
    host = normalize_host(host)
    if not rec or not host or not is_academic_domain(rec) or matches_domain(host, rec) or _IPV4.match(host):
        return None
    label = main_label(rec)
    if len(label) < 4:
        return None
    label_sk = skeleton(label)
    host_main = main_label(host)
    if len(label) >= 6 and host_main != label and _one_typo_away(skeleton(host_main), label_sk):
        return rec
    sec, svc = domain_lure_words(host)
    if not (sec or svc or campus_department_words(host) or is_login_like(f"https://{host}/")):
        return None
    tokens = [t for part in host.split(".") for t in part.split("-") if t]
    if any(skeleton(t) == label_sk for t in tokens) or label_sk in skeleton(host_main):
        return rec
    return None


# ---------------------------------------------------------------- same university name, different ending
# ntpu.com, ntpu.tw, ntpu.net: anyone can buy these. Names of 4+ letters only, because short ones belong to
# real companies (ui.com is Ubiquiti). Even long names can (columbia.com is a clothing brand), so this alone
# is a caution; it becomes "Suspicious" only together with a sign-in hint (see url_scanner).
STRONG_LOGIN_HINTS = ("sso", "login", "log-in", "logon", "signin", "sign-in", "auth", "password", "passwd",
                      "webmail", "verify", "cas", "idp", "mfa", "2fa")


def trusted_name_other_ending(host: str, trusted: Dict[str, str]) -> Optional[str]:
    host = normalize_host(host)
    if not host or _IPV4.match(host) or find_trusted(host, trusted) or is_academic_domain(host) or is_brand_owned(host):
        return None
    main = main_label(host)
    for domain in trusted:
        domain = normalize_host(domain)
        if is_academic_domain(domain) and len(main_label(domain)) >= 4 and main == main_label(domain):
            return domain
    return None


def has_strong_login_hint(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    host = normalize_host(parsed.hostname or "")
    sub = host[: -len(registrable_domain(host))].rstrip(".") if registrable_domain(host) else ""
    words = re.split(r"[\s./\-_?=&]+", f"{sub} {parsed.path or ''}".lower())
    return any(w in STRONG_LOGIN_HINTS for w in words if w)


# ---------------------------------------------------------------- misspelled sign-in page on a real domain
# ssa.ntpu.edu.tw instead of sso.ntpu.edu.tw. Only the university can create names under its own domain, so
# this is not an attacker's page; but the student is not on the sign-in page they meant to open.
LOGIN_SUBDOMAINS = ("sso", "login", "signin", "portal", "webmail", "auth")


def _near_miss(label: str, target: str) -> bool:
    if label == target:
        return False
    if skeleton(label) == skeleton(target):
        return True  # ss0 for sso
    if len(label) == len(target) >= 3 and label[0] == target[0]:
        diff = sum(1 for x, y in zip(label, target) if x != y)
        if diff == 1:
            return True  # ssa for sso
    return len(target) >= 4 and _one_typo_away(label, target)  # logn, lgoin for login


def misspelled_login_subdomain(host: str, trusted: Dict[str, str], portal_host: str = "") -> Optional[str]:
    """For a host under a trusted domain, the sign-in host it looks like a misspelling of, or None."""
    host = normalize_host(host)
    match = find_trusted(host, trusted) if host else None
    if not match or host == normalize_host(match[0]):
        return None
    parent = normalize_host(match[0])
    label = host[: -len(parent) - 1].split(".")[0]
    targets = list(LOGIN_SUBDOMAINS)
    portal_host = normalize_host(portal_host)
    if portal_host and portal_host != host and matches_domain(portal_host, parent) and portal_host != parent:
        targets.insert(0, portal_host[: -len(parent) - 1].split(".")[0])
    if label in targets:
        return None
    for target in targets:
        if _near_miss(label, target):
            return f"{target}.{parent}"
    return None


def first_party(link_host: str, sender_domain: str) -> bool:
    """True when the link is on the sender's own registrable domain (portal.westbrook.edu from westbrook.edu)."""
    if not link_host or not sender_domain:
        return False
    return matches_domain(link_host, registrable_domain(sender_domain))


# ---------------------------------------------------------------- authority titles in a display name
AUTHORITY_TITLE_RE = re.compile(
    r"\b(?:prof\.?|professor|dr\.?|dean|director|president|provost|chancellor|rector|registrar|bursar|ceo|cfo|coo|"
    r"cto|chief|head of \w+|vice[- ]president|treasurer|chair(?:man|woman|person)?|principal|manager|supervisor|"
    r"hr|human resources|payroll|help ?desk|it (?:support|services?|department|team|help)|support|security|"
    r"admin(?:istrator|istration)?|accounts?(?: payable| receivable)?|billing|finance|financial aid|office|"
    r"services?|team|department|committee|administration|disbursement|quota)\b",
    re.IGNORECASE,
)


def authority_title(display_name: str) -> Optional[str]:
    match = AUTHORITY_TITLE_RE.search(display_name or "")
    return match.group(0) if match else None
