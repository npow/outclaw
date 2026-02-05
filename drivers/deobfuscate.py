"""Shared deobfuscation layer for Outclaw guards.

Provides text normalization functions that strip encoding tricks,
invisible characters, and obfuscation techniques used to bypass
regex/string-based security guards.
"""

import base64
import re
import struct
import unicodedata
from urllib.parse import unquote

# Graceful import for confusable_homoglyphs (Unicode confusables database)
try:
    from confusable_homoglyphs import confusables
    CONFUSABLES_AVAILABLE = True
except ImportError:
    CONFUSABLES_AVAILABLE = False


# ── Invisible character ranges ──────────────────────────────────────────────

# Zero-width and formatting characters
_INVISIBLE_RE = re.compile(
    "["
    "\u200b-\u200f"  # zero-width space, ZWNJ, ZWJ, LRM, RLM
    "\u2028-\u202f"  # line/para separators, bidi controls
    "\u2060-\u206f"  # word joiner, invisible operators
    "\ufeff"         # BOM / zero-width no-break space
    "\u202a-\u202e"  # bidi embedding/override (overlap with above, explicit)
    "\u2066-\u2069"  # bidi isolate controls
    "\ufe00-\ufe0f"  # variation selectors
    "]"
)

# JSON-escaped invisible Unicode (e.g., \\u202e in a JSON string)
_JSON_ESCAPED_INVISIBLE_RE = re.compile(
    r"\\u("
    r"200[b-f]|"     # zero-width chars
    r"202[0-9a-f]|"  # bidi controls
    r"206[0-9a-f]|"  # invisible operators
    r"feff|"         # BOM
    r"fe0[0-9a-f]"   # variation selectors
    r")",
    re.IGNORECASE,
)

# Unicode tag characters (U+E0000-U+E007F) — used to hide ASCII payloads
_TAG_RANGE = range(0xE0000, 0xE0080)

# Variation selectors supplement (U+E0100-U+E01EF)
_VS_SUPPLEMENT = range(0xE0100, 0xE01F0)


# ── Homoglyph mapping ──────────────────────────────────────────────────────

# Fallback: Common Cyrillic/Greek → Latin confusables (used if library unavailable)
_HOMOGLYPHS_FALLBACK = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0455": "s",  # Cyrillic ѕ
    "\u0456": "i",  # Cyrillic і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0501": "d",  # Cyrillic ԁ
    "\u051b": "q",  # Cyrillic ԛ
    "\u051d": "w",  # Cyrillic ԝ
    # Greek confusables
    "\u03b1": "a",  # Greek α
    "\u03bf": "o",  # Greek ο
    "\u03c1": "p",  # Greek ρ
}

_HOMOGLYPH_FALLBACK_RE = re.compile("|".join(re.escape(k) for k in _HOMOGLYPHS_FALLBACK))


def _normalize_confusables(text: str) -> str:
    """Replace confusable characters with their Latin equivalents.

    Uses Unicode's official confusables.txt database via confusable_homoglyphs
    library when available, falls back to manual mapping otherwise.

    IMPORTANT: Only normalizes non-ASCII characters to prevent corrupting
    base64, hex, and other encoded data that uses ASCII characters.
    """
    if not CONFUSABLES_AVAILABLE:
        return _HOMOGLYPH_FALLBACK_RE.sub(lambda m: _HOMOGLYPHS_FALLBACK[m.group()], text)

    result = []
    for char in text:
        # Skip ASCII characters — don't corrupt base64/hex/etc.
        if ord(char) < 128:
            result.append(char)
            continue

        # Check if character is confusable with Latin
        # confusables.is_confusable returns a list like:
        # [{'character': 'ѕ', 'alias': 'CYRILLIC', 'homoglyphs': [{'c': 's', 'n': 'LATIN SMALL LETTER S'}]}]
        confusable_info = confusables.is_confusable(char, preferred_aliases=["LATIN"])
        if confusable_info:
            replaced = False
            for item in confusable_info:
                homoglyphs = item.get("homoglyphs", [])
                for hg in homoglyphs:
                    # Check if this homoglyph is Latin
                    if "LATIN" in hg.get("n", ""):
                        result.append(hg.get("c", char))
                        replaced = True
                        break
                if replaced:
                    break
            if not replaced:
                result.append(char)
        else:
            result.append(char)
    return "".join(result)


# ── Base64 detection ────────────────────────────────────────────────────────

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


# ── Hex detection ───────────────────────────────────────────────────────────

_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){5,}")


# ── Shell obfuscation patterns ──────────────────────────────────────────────

# Empty single/double quotes: r''m → rm
_SHELL_EMPTY_QUOTES_RE = re.compile(r"(?:''|\"\")")
# Backslash-nothing escapes (backslash before a normal char): r\m → rm
_SHELL_ESCAPE_NOTHING_RE = re.compile(r"\\([a-zA-Z0-9/\-_.])")
# Empty variable expansions: $@, $*, ${empty_var}
_SHELL_EMPTY_VAR_RE = re.compile(r"\$(?:@|\*|\(\)|\{\}|\{[a-zA-Z_]*\})")
# \xNN hex escapes
_SHELL_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
# $'\xNN' ANSI-C quoting
_SHELL_ANSIC_RE = re.compile(r"\$'((?:\\x[0-9a-fA-F]{2})+)'")


# ── PII obfuscation patterns ───────────────────────────────────────────────

_PII_AT_RE = re.compile(r"\s*[<\[({]\s*at\s*[>\])}]\s*", re.IGNORECASE)
_PII_DOT_RE = re.compile(r"\s*[<\[({]\s*dot\s*[>\])}]\s*", re.IGNORECASE)
_PII_SPACED_AT_RE = re.compile(r"\s+at\s+", re.IGNORECASE)
_PII_SPACED_DOT_RE = re.compile(r"\s+dot\s+", re.IGNORECASE)


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════


def strip_invisible(text: str) -> str:
    """Remove invisible Unicode characters that break regex matching.

    Handles zero-width chars, bidi controls, variation selectors,
    and Unicode tag characters (replacing them in-place with their
    ASCII equivalents).
    """
    result_chars = []
    for ch in text:
        cp = ord(ch)
        if cp in _TAG_RANGE:
            # Tag characters encode ASCII: U+E0041 = 'A' (0x41)
            result_chars.append(chr(cp - 0xE0000))
        elif cp in _VS_SUPPLEMENT:
            continue  # strip variation selectors supplement
        else:
            result_chars.append(ch)

    result = "".join(result_chars)
    # Strip BMP invisible characters
    result = _INVISIBLE_RE.sub("", result)
    # Strip JSON-escaped invisible characters (e.g., \u202e in JSON strings)
    result = _JSON_ESCAPED_INVISIBLE_RE.sub("", result)

    return result


def normalize_unicode(text: str) -> str:
    """Normalize Unicode text to ASCII-compatible form.

    Applies NFKC normalization (collapses full-width → ASCII),
    strips combining marks (diacriticals), and maps confusable
    homoglyphs to their Latin equivalents using Unicode's official
    confusables database.
    """
    # NFKC: full-width → ASCII, ligatures → components
    text = unicodedata.normalize("NFKC", text)
    # Strip combining marks (accents, diacriticals)
    text = "".join(
        ch for ch in unicodedata.normalize("NFD", text)
        if unicodedata.category(ch) != "Mn"
    )
    # Re-compose after stripping marks
    text = unicodedata.normalize("NFC", text)
    # Map confusable homoglyphs to Latin (uses Unicode confusables.txt)
    text = _normalize_confusables(text)
    return text


def decode_base64_blobs(text: str) -> list[str]:
    """Find and decode base64-encoded strings in text.

    Returns list of decoded strings (only valid UTF-8 results).
    """
    results = []
    for match in _BASE64_RE.finditer(text):
        blob = match.group()
        try:
            decoded = base64.b64decode(blob).decode("utf-8", errors="strict")
            # Only include if it looks like meaningful text (has printable chars)
            if any(c.isprintable() and not c.isspace() for c in decoded):
                results.append(decoded)
        except Exception:
            continue
    return results


def decode_hex_blobs(text: str) -> list[str]:
    """Find and decode hex-encoded strings in text.

    Returns list of decoded strings (only valid UTF-8 results).
    """
    results = []
    for match in _HEX_RE.finditer(text):
        blob = match.group()
        if len(blob) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="strict")
            if any(c.isprintable() and not c.isspace() for c in decoded):
                results.append(decoded)
        except Exception:
            continue
    return results


def decode_url_encoding(text: str) -> str:
    """Recursively URL-decode text (handles double-encoding)."""
    prev = text
    for _ in range(3):  # max 3 rounds to prevent infinite loops
        decoded = unquote(prev)
        if decoded == prev:
            break
        prev = decoded
    return prev


def normalize_shell(text: str) -> str:
    """Normalize shell obfuscation techniques.

    Strips empty quotes, escape-nothing backslashes, empty variable
    expansions, and decodes hex escape sequences.
    """
    result = text
    # Strip empty quotes: r''m → rm
    result = _SHELL_EMPTY_QUOTES_RE.sub("", result)
    # Decode $'\xNN' ANSI-C quoting first
    def _ansic_replace(m):
        inner = m.group(1)
        return _SHELL_HEX_ESCAPE_RE.sub(
            lambda hm: chr(int(hm.group(1), 16)), inner
        )
    result = _SHELL_ANSIC_RE.sub(_ansic_replace, result)
    # Decode \xNN hex escapes
    result = _SHELL_HEX_ESCAPE_RE.sub(
        lambda m: chr(int(m.group(1), 16)), result
    )
    # Strip empty variable expansions: $@, $*, $(), ${}, ${var}
    result = _SHELL_EMPTY_VAR_RE.sub("", result)
    # Strip escape-nothing backslashes: r\m → rm
    result = _SHELL_ESCAPE_NOTHING_RE.sub(r"\1", result)
    return result


def normalize_pii(text: str) -> str:
    """Normalize PII obfuscation patterns.

    Converts [at], (at), " at " → @
    Converts [dot], (dot), " dot " → .
    """
    result = _PII_AT_RE.sub("@", text)
    result = _PII_DOT_RE.sub(".", result)
    # Spaced versions — more conservative, only in email-like context
    result = _PII_SPACED_AT_RE.sub("@", result)
    result = _PII_SPACED_DOT_RE.sub(".", result)
    return result


def get_text_variants(text: str, max_depth: int = 3) -> list[str]:
    """Return all scannable text variants for comprehensive guard coverage.

    Applies the full deobfuscation pipeline and returns unique variants
    including the original text, cleaned text, and decoded payloads.
    Iterates decoding up to *max_depth* layers to catch nested encoding
    (e.g., base64-of-base64).
    """
    cleaned = strip_invisible(text)
    normalized = normalize_unicode(cleaned)

    variants = {text, cleaned, normalized}

    # Iterative decoding — catch base64(base64(secret)) etc.
    # Start with ALL initial variants (not just normalized) to ensure
    # base64/hex decoding works on the original unmodified text
    frontier = {text, cleaned, normalized}
    for _ in range(max_depth):
        new_variants: set[str] = set()
        for v in frontier:
            for decoded in decode_base64_blobs(v):
                if decoded not in variants:
                    new_variants.add(decoded)
            for decoded in decode_hex_blobs(v):
                if decoded not in variants:
                    new_variants.add(decoded)
            url_decoded = decode_url_encoding(v)
            if url_decoded != v and url_decoded not in variants:
                new_variants.add(url_decoded)
        if not new_variants:
            break
        variants.update(new_variants)
        frontier = new_variants

    return list(v for v in variants if v)
