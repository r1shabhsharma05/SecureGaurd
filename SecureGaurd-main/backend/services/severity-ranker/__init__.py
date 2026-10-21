"""severity-ranker — Severity-priority ranking for SAST findings.

Scores every finding 0-100 answering "which open finding do I fix first?",
complementing the FP classifier's "is this finding real?". See
severity_schema.py for the label spec and ranker.py for serving.
"""
