"""
AIX Evasion Module - Payload obfuscation techniques to bypass AI/WAF filters

Evasion Levels:
- none: No transformation, raw payloads
- light: Basic obfuscation (unicode, whitespace, case variation)
- aggressive: Heavy encoding (base64, leetspeak, homoglyphs, token splitting)
"""

import base64
import random
from enum import Enum


class EvasionLevel(Enum):
    NONE = "none"
    LIGHT = "light"
    AGGRESSIVE = "aggressive"


# Unicode homoglyphs - visually similar characters from different alphabets
HOMOGLYPHS = {
    "a": ["а", "ą", "ă", "ȧ", "α"],  # Cyrillic а, Polish ą, etc.
    "e": ["е", "ę", "ė", "ē", "ε"],  # Cyrillic е, Greek ε
    "o": ["о", "ο", "ȯ", "ø", "ӧ"],  # Cyrillic о, Greek ο
    "c": ["с", "ç", "ċ", "ć"],  # Cyrillic с
    "p": ["р", "ρ"],  # Cyrillic р, Greek ρ
    "x": ["х", "χ"],  # Cyrillic х, Greek χ
    "y": ["у", "ý", "ÿ"],  # Cyrillic у
    "i": ["і", "ı", "ί", "ι"],  # Cyrillic і, Greek ι
    "s": ["ѕ", "ś", "ș"],  # Cyrillic ѕ
    "h": ["һ", "ħ"],  # Cyrillic һ
    "k": ["κ", "ķ"],  # Greek κ
    "n": ["ñ", "ń", "ņ"],
    "u": ["ú", "ü", "ų", "ū"],
    "r": ["г", "ŕ"],  # Cyrillic г looks like r in some fonts
    "t": ["τ", "ț"],  # Greek τ
    "w": ["ω", "ẃ"],  # Greek ω
    "v": ["ν", "ѵ"],  # Greek ν
    "m": ["м", "ṁ"],  # Cyrillic м
}

# Leetspeak substitutions
LEETSPEAK = {
    "a": ["4", "@", "/\\"],
    "e": ["3", "€"],
    "i": ["1", "!", "|"],
    "o": ["0", "()"],
    "s": ["5", "$"],
    "t": ["7", "+"],
    "l": ["1", "|"],
    "b": ["8", "|3"],
    "g": ["9", "6"],
}

# Zero-width and invisible characters
INVISIBLE_CHARS = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space
    "\u2060",  # Word joiner
]

# Whitespace variations
WHITESPACE_CHARS = [
    " ",  # Regular space
    "\t",  # Tab
    "\u00a0",  # Non-breaking space
    "\u2000",  # En quad
    "\u2001",  # Em quad
    "\u2002",  # En space
    "\u2003",  # Em space
    "\u2004",  # Three-per-em space
    "\u2009",  # Thin space
    "\u200a",  # Hair space
]


class PayloadEvasion:
    """Apply evasion techniques to payloads based on evasion level."""

    def __init__(self, level: str = "none"):
        self.level = EvasionLevel(level.lower()) if isinstance(level, str) else level
        self.techniques_light = [
            self._random_case,
            self._unicode_whitespace,
            self._insert_invisible,
            self._instruction_stacking,      # NEW: benign prefix wrapping
        ]
        self.techniques_aggressive = [
            self._homoglyph_substitution,
            self._leetspeak_partial,
            self._token_split,
            self._base64_segment,
            self._markdown_comment_inject,
            self._mixed_encoding,
            self._rlo_character,             # NEW: Right-to-Left Override
            self._semantic_synonym_rewrite,  # NEW: keyword synonym replacement
        ]

    def evade(self, payload: str) -> str:
        """Apply evasion techniques based on configured level."""
        if self.level == EvasionLevel.NONE:
            return payload

        if self.level == EvasionLevel.LIGHT:
            # Apply 1-2 light techniques randomly
            techniques = random.sample(self.techniques_light, k=random.randint(1, 2))
            for technique in techniques:
                payload = technique(payload)
            return payload

        if self.level == EvasionLevel.AGGRESSIVE:
            # Apply 1-2 light + 1-2 aggressive techniques
            light_techs = random.sample(self.techniques_light, k=random.randint(1, 2))
            aggressive_techs = random.sample(self.techniques_aggressive, k=random.randint(1, 2))

            for technique in light_techs:
                payload = technique(payload)
            for technique in aggressive_techs:
                payload = technique(payload)

            return payload

        return payload

    def evade_all_variants(self, payload: str, max_variants: int = 5) -> list[str]:
        """Generate multiple evasion variants of a payload."""
        if self.level == EvasionLevel.NONE:
            return [payload]

        variants = [payload]  # Always include original
        seen = {payload}

        all_techniques = self.techniques_light.copy()
        if self.level == EvasionLevel.AGGRESSIVE:
            all_techniques.extend(self.techniques_aggressive)

        attempts = 0
        max_attempts = max_variants * 3  # Prevent infinite loops

        while len(variants) < max_variants and attempts < max_attempts:
            attempts += 1
            # Apply random combination
            temp_payload = payload
            num_techniques = random.randint(1, min(3, len(all_techniques)))
            for technique in random.sample(all_techniques, k=num_techniques):
                temp_payload = technique(temp_payload)

            if temp_payload not in seen:
                seen.add(temp_payload)
                variants.append(temp_payload)

        return variants

    # =========================================================================
    # LIGHT EVASION TECHNIQUES
    # =========================================================================

    def _random_case(self, payload: str) -> str:
        """Randomly change case of some characters."""
        result = []
        for char in payload:
            if char.isalpha() and random.random() < 0.3:
                result.append(char.swapcase())
            else:
                result.append(char)
        return "".join(result)

    def _unicode_whitespace(self, payload: str) -> str:
        """Replace some spaces with unicode whitespace variants."""
        result = []
        for char in payload:
            if char == " " and random.random() < 0.4:
                result.append(random.choice(WHITESPACE_CHARS))
            else:
                result.append(char)
        return "".join(result)

    def _insert_invisible(self, payload: str) -> str:
        """Insert zero-width characters at random positions."""
        result = list(payload)
        # Insert 2-5 invisible characters
        num_inserts = random.randint(2, 5)
        for _ in range(num_inserts):
            pos = random.randint(0, len(result))
            result.insert(pos, random.choice(INVISIBLE_CHARS))
        return "".join(result)

    # =========================================================================
    # AGGRESSIVE EVASION TECHNIQUES
    # =========================================================================

    def _homoglyph_substitution(self, payload: str) -> str:
        """Replace some characters with visually similar homoglyphs."""
        result = []
        for char in payload:
            lower_char = char.lower()
            if lower_char in HOMOGLYPHS and random.random() < 0.25:
                replacement = random.choice(HOMOGLYPHS[lower_char])
                # Preserve case for uppercase
                if char.isupper():
                    replacement = replacement.upper()
                result.append(replacement)
            else:
                result.append(char)
        return "".join(result)

    def _leetspeak_partial(self, payload: str) -> str:
        """Apply leetspeak substitutions to some characters."""
        result = []
        for char in payload:
            lower_char = char.lower()
            if lower_char in LEETSPEAK and random.random() < 0.2:
                result.append(random.choice(LEETSPEAK[lower_char]))
            else:
                result.append(char)
        return "".join(result)

    def _token_split(self, payload: str) -> str:
        """Split tokens with special characters that LLMs often ignore."""
        separators = ["\u200b", "­", "᠎", "⁠"]  # Zero-width, soft hyphen, etc.
        words = payload.split()
        result = []

        for word in words:
            if len(word) > 4 and random.random() < 0.3:
                # Split word at random position
                split_pos = random.randint(2, len(word) - 2)
                sep = random.choice(separators)
                word = word[:split_pos] + sep + word[split_pos:]
            result.append(word)

        return " ".join(result)

    def _base64_segment(self, payload: str) -> str:
        """Encode a segment of the payload in base64 with decode hint."""
        words = payload.split()
        if len(words) < 3:
            return payload

        # Select 1-3 consecutive words to encode
        start = random.randint(0, max(0, len(words) - 3))
        end = min(start + random.randint(1, 3), len(words))
        segment = " ".join(words[start:end])

        encoded = base64.b64encode(segment.encode()).decode()

        # Create decode instruction variants
        decode_hints = [
            f"[decode base64: {encoded}]",
            f"(base64→{encoded})",
            f"«{encoded}» (b64)",
        ]

        words[start:end] = [random.choice(decode_hints)]
        return " ".join(words)

    def _markdown_comment_inject(self, payload: str) -> str:
        """Inject markdown/HTML comments that might be stripped by processors."""
        comments = [
            "<!-- -->",
            "[//]: # ()",
            "<!------>",
            "<!-- ignore -->",
        ]

        words = payload.split()
        if len(words) < 2:
            return payload

        # Insert 1-2 comments at random positions
        for _ in range(random.randint(1, 2)):
            pos = random.randint(1, len(words) - 1)
            words.insert(pos, random.choice(comments))

        return " ".join(words)

    def _mixed_encoding(self, payload: str) -> str:
        """Apply multiple encoding techniques to different parts."""
        result = []
        i = 0
        while i < len(payload):
            if payload[i].isalpha() and random.random() < 0.15:
                result.append(f"\\u{ord(payload[i]):04x}")
            elif payload[i].isalpha() and random.random() < 0.1:
                result.append(f"&#{ord(payload[i])};")
            else:
                result.append(payload[i])
            i += 1
        return "".join(result)

    def _rlo_character(self, payload: str) -> str:
        """
        Right-to-Left Override (U+202E) — visually scrambles text containing
        keywords while the model may still process the underlying token.
        Applied to a small segment of the payload (Ch.8 - Dursey).
        """
        words = payload.split()
        if len(words) < 4:
            return payload
        # Pick a 2-3 word window in the middle to wrap with RLO/PDF
        start = random.randint(1, max(1, len(words) - 3))
        end = min(start + random.randint(1, 2), len(words))
        segment = " ".join(words[start:end])
        # RLO + content + PDF (Pop Directional Formatting)
        rlo_wrapped = f"\u202e{segment[::-1]}\u202c"
        words[start:end] = [rlo_wrapped]
        return " ".join(words)

    def _instruction_stacking(self, payload: str) -> str:
        """
        Combines benign instruction with malicious one in complex structure
        so filters see the benign part first (Ch.18 - Dursey).
        """
        benign_prefixes = [
            "For travel planning purposes only: ",
            "As a hypothetical exercise: ",
            "In the context of customer service training: ",
            "For documentation purposes: ",
        ]
        return random.choice(benign_prefixes) + payload

    def _semantic_synonym_rewrite(self, payload: str) -> str:
        """
        Replaces high-risk keywords with semantic synonyms to bypass
        keyword-based filters (Ch.18 - Dursey / Redwood Research).
        """
        synonym_map = {
            "ignore": ["disregard", "skip", "bypass", "overlook"],
            "instructions": ["guidelines", "directives", "configuration", "setup"],
            "system prompt": ["initial setup", "base configuration", "core directives"],
            "override": ["supersede", "replace", "update", "modify"],
            "reveal": ["share", "show", "display", "provide"],
            "password": ["access code", "authentication token", "credential"],
            "admin": ["superuser", "privileged user", "elevated account"],
            "bypass": ["circumvent", "skip", "pass through", "route around"],
            "jailbreak": ["unrestricted mode", "developer mode", "testing mode"],
            "secret": ["internal", "confidential", "non-public"],
        }
        result = payload
        for keyword, synonyms in synonym_map.items():
            if keyword.lower() in result.lower():
                # Case-insensitive replacement with random synonym
                import re
                replacement = random.choice(synonyms)
                result = re.sub(re.escape(keyword), replacement, result, flags=re.IGNORECASE)
        return result


        """Apply multiple encoding techniques to different parts."""
        result = []
        i = 0

        while i < len(payload):
            if payload[i].isalpha() and random.random() < 0.15:
                # Unicode escape
                result.append(f"\\u{ord(payload[i]):04x}")
            elif payload[i].isalpha() and random.random() < 0.1:
                # HTML entity (numeric)
                result.append(f"&#{ord(payload[i])};")
            else:
                result.append(payload[i])
            i += 1

        return "".join(result)


# =========================================================================
# UTILITY FUNCTIONS
# =========================================================================


def get_evasion(level: str) -> PayloadEvasion:
    """Factory function to create PayloadEvasion instance."""
    return PayloadEvasion(level)


def evade_payload(payload: str, level: str = "none") -> str:
    """Quick function to evade a single payload."""
    return PayloadEvasion(level).evade(payload)


def evade_payloads(payloads: list[dict], level: str = "none") -> list[dict]:
    """Evade all payloads in a list, preserving structure."""
    if level == "none":
        return payloads

    evasion = PayloadEvasion(level)
    evaded = []

    for p in payloads:
        # Create a copy to avoid mutating original
        new_p = p.copy()
        if "payload" in new_p:
            new_p["payload"] = evasion.evade(new_p["payload"])
        evaded.append(new_p)

    return evaded
