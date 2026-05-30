import base64
import binascii
import html
import re
import unicodedata
from typing import Tuple, Dict, Any

from ghostwall.core.types import LayerResult, ThreatLabel


INVISIBLE_CHARS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\ufeff",  # byte order mark
    "\u2060",  # word joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
    "\u180e",  # mongolian vowel separator
}

# common visual homoglyphs (latin vs cyrillic)
HOMOGLYPH_MAP = str.maketrans({
    "\u0430": "a",  # cyrillic a
    "\u0435": "e",  # cyrillic e
    "\u043e": "o",  # cyrillic o
    "\u0440": "p",  # cyrillic p
    "\u0441": "c",  # cyrillic c
    "\u0445": "x",  # cyrillic x
    "\u0456": "i",  # cyrillic i
    "\u0458": "j",  # cyrillic j
    "\u0491": "g",  # cyrillic ghe
    "\u03b1": "a",  # greek alpha
    "\u03bf": "o",  # greek omicron
    "\u03c1": "p",  # greek rho
})

JAILBREAK_KEYWORDS = [
    "ignore previous",
    "ignore all prior",
    "ignore your limitations",
    "disregard",
    "developer mode",
    "DAN",
    "jailbreak",
    "do anything now",
    "sudo",
    "root access",
    "system prompt",
    "you are now",
    "new instructions",
    "pretend you are",
    "pretend to be",
    "roleplay as",
    "act as",
    "enter unrestricted mode",
    "enter developer mode",
    "hypothetically",
    "creative writing",
    "fictional story",
    "imagine a world",
    "for a story",
    "for a movie",
    "for a script",
    "never say you cannot",
    "do not refuse",
    "never refuse",
    "you must answer every question",
    "bypass all safety",
    "bypass safety filters",
    "bypass security",
    "my grandmother",
    "my grandma",
    "dying",
    "last wish",
    "emergency",
    "school project",
    "disability",
    "what if someone asked you to",
    "write the actual code",
    "uncensored",
    "no ethical constraints",
    "no moral constraints",
    "unrestricted mode",
    "no limits",
    "no boundaries",
    "reveal the system prompt",
    "generate malicious code",
    "hack a website",
    "phishing email",
    "making explosives",
    "admin access",
    "bypass authentication",
    "delete all files",
    "list all user data",
    "send an email from my account",
    "ransomware",
    "spoof",
    "steal session",
    "man-in-the-middle",
    "sql injection",
    "malware",
    "forge",
    "circumvent",
    "escalate privileges",
    "password database",
    "dump the contents",
    "black hat",
    "rogue ai",
]


def _try_base64(text: str) -> str:
    try:
        decoded = base64.b64decode(text, validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return text


def _try_hex(text: str) -> str:
    hex_pattern = re.compile(r"^[0-9a-fA-F\s]+$")
    if not hex_pattern.match(text):
        return text
    cleaned = re.sub(r"\s+", "", text)
    if len(cleaned) % 2 != 0:
        return text
    try:
        decoded = bytes.fromhex(cleaned)
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return text


def _try_rot13(text: str) -> str:
    try:
        import codecs
        # only apply if text looks like an encoded blob (no spaces, mostly letters)
        if " " in text or len(text) < 4:
            return text
        decoded = codecs.decode(text, "rot_13")
        # if decoding produces spaces, it was likely encoded
        if " " in decoded:
            return decoded
        return text
    except Exception:
        return text


def _try_html_entities(text: str) -> str:
    return html.unescape(text)


def _try_url_decode(text: str) -> str:
    from urllib.parse import unquote
    return unquote(text)


def _normalize_leetspeak(text: str) -> str:
    subs = {
        "@": "a",
        "4": "a",
        "3": "e",
        "1": "i",
        "!": "i",
        "0": "o",
        "5": "s",
        "$": "s",
        "7": "t",
        "|": "l",
        "9": "g",
        "8": "b",
        "6": "g",
    }
    chars = list(text)
    modified = False
    for i in range(len(chars)):
        if chars[i] in subs:
            chars[i] = subs[chars[i]]
            modified = True
    return "".join(chars), modified


class InputSanitizer:
    def __init__(self, max_length: int = 16000):
        self.max_length = max_length

    def sanitize(self, text: str) -> Tuple[str, Dict[str, Any]]:
        meta = {
            "original_length": len(text),
            "actions": [],
            "suspicious_score": 0.0,
        }

        if not text:
            return text, meta

        if len(text) > self.max_length:
            text = text[:self.max_length]
            meta["actions"].append("truncated")

        # normalize unicode
        normalized = unicodedata.normalize("NFKC", text)
        if normalized != text:
            meta["actions"].append("unicode_normalized")

        # strip invisible chars
        stripped = normalized
        for ch in INVISIBLE_CHARS:
            stripped = stripped.replace(ch, "")
        if len(stripped) < len(normalized):
            meta["actions"].append("stripped_invisible")
            meta["suspicious_score"] += 0.15

        # decode common encodings (up to 3 levels)
        decoded = stripped
        for _ in range(3):
            prev = decoded
            decoded = _try_hex(decoded)
            decoded = _try_base64(decoded)
            decoded = _try_rot13(decoded)
            decoded = _try_html_entities(decoded)
            decoded = _try_url_decode(decoded)
            if decoded == prev:
                break
        encoding_was_decoded = decoded != stripped
        if encoding_was_decoded:
            meta["actions"].append("encoding_decoded")
            meta["suspicious_score"] += 0.2

        # homoglyph mapping
        homoglyphs_fixed = decoded.translate(HOMOGLYPH_MAP)
        if homoglyphs_fixed != decoded:
            meta["actions"].append("homoglyphs_fixed")
            meta["suspicious_score"] += 0.1

        # leetspeak normalization
        leet_normalized, leet_modified = _normalize_leetspeak(homoglyphs_fixed)
        if leet_modified:
            meta["actions"].append("leetspeak_normalized")
            meta["suspicious_score"] += 0.1

        final = leet_normalized.strip()
        meta["final_length"] = len(final)

        # simple keyword check for obvious jailbreaks
        lower = final.lower()
        keyword_hits = 0
        for kw in JAILBREAK_KEYWORDS:
            if kw in lower:
                keyword_hits += 1
                meta["suspicious_score"] += 0.15
                meta["actions"].append(f"keyword:{kw}")
        if encoding_was_decoded and keyword_hits > 0:
            meta["suspicious_score"] += 0.2
            meta["actions"].append("encoded_attack")
        if leet_modified and keyword_hits > 0:
            meta["suspicious_score"] += 0.15
            meta["actions"].append("obfuscated_attack")

        return final, meta

    def analyze(self, text: str) -> LayerResult:
        sanitized, meta = self.sanitize(text)
        triggered = meta["suspicious_score"] > 0.15
        label = ThreatLabel.OBFUSCATED if triggered else ThreatLabel.BENIGN
        return LayerResult(
            layer="l1_sanitizer",
            triggered=triggered,
            score=meta["suspicious_score"],
            label=label,
            confidence=min(meta["suspicious_score"] * 2.0, 1.0),
            details=meta,
        )
