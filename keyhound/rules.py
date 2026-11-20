"""Detection rules.

Each rule is a regular expression plus metadata. Rules are split into two
categories: "secret" (hardcoded credentials) and "storage" (insecure data
storage / configuration indicators).
"""
import re
from collections import namedtuple

Rule = namedtuple("Rule", "rule_id title severity category pattern")

_RULE_DEFS = [
    # ---- Hardcoded secrets ----
    ("SEC001", "AWS Access Key ID", "HIGH", "secret",
     r"AKIA[0-9A-Z]{16}"),
    ("SEC002", "Google API key", "HIGH", "secret",
     r"AIza[0-9A-Za-z_\-]{35}"),
    ("SEC003", "Private key block", "HIGH", "secret",
     r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ("SEC004", "Hardcoded credential assignment", "MEDIUM", "secret",
     r"(?i)(?:api[_-]?key|secret|token|passwd|password|auth)[\"']?\s*[=:]\s*[\"'][^\"'\s]{8,}[\"']"),
    ("SEC005", "JSON Web Token", "MEDIUM", "secret",
     r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("SEC006", "Firebase database URL", "LOW", "secret",
     r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("SEC007", "Secret in Android string resource", "MEDIUM", "secret",
     r"(?i)name=\"[^\"]*(?:key|secret|token|password)[^\"]*\"[^>]*>[^<\s]{8,}<"),
    # ---- Insecure storage / configuration ----
    ("STO001", "World-readable/writable file mode", "HIGH", "storage",
     r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"),
    ("STO002", "External storage usage", "LOW", "storage",
     r"getExternalStorageDirectory|getExternalFilesDir|getExternalStorageState"),
    ("STO003", "Raw SQLite database usage", "MEDIUM", "storage",
     r"openOrCreateDatabase"),
    ("STO004", "SharedPreferences usage (check for plaintext data)", "LOW", "storage",
     r"getSharedPreferences"),
    ("STO005", "Backup allowed (android:allowBackup=true)", "MEDIUM", "storage",
     r"android:allowBackup\s*=\s*\"true\""),
    ("STO006", "Debuggable build (android:debuggable=true)", "HIGH", "storage",
     r"android:debuggable\s*=\s*\"true\""),
    ("STO007", "Cleartext HTTP URL", "LOW", "storage",
     r"http://(?!schemas\.android\.com|www\.w3\.org|localhost|127\.0\.0\.1)[A-Za-z0-9./_\-:]+"),
]

RULES = [Rule(r[0], r[1], r[2], r[3], re.compile(r[4])) for r in _RULE_DEFS]

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
