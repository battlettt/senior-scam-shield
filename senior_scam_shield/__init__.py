"""Senior Scam Shield: an offline scam checker for texts, emails, and calls."""

from .verdict import LIKELY_SCAM, LOOKS_SAFE, SUSPICIOUS, analyze

__all__ = ["analyze", "LIKELY_SCAM", "SUSPICIOUS", "LOOKS_SAFE"]
