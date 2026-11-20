import zipfile

from .rules import RULES

SKIP_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4",
                   ".ogg", ".ttf", ".otf")
MAX_FILE_SIZE = 10 * 1024 * 1024  # skip entries larger than 10 MB (zip-bomb guard)
BINARY_XML_MAGIC = b"\x03\x00\x08\x00"  # header of compiled Android binary XML


def mask(value):
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * 6 + value[-2:]


def scan_apk(apk_path, should_stop=lambda: False):
    findings, seen = [], set()
    stats = {"files_total": 0, "files_scanned": 0, "files_skipped": 0, "aborted": False}

    with zipfile.ZipFile(apk_path) as apk:
        for info in apk.infolist():
            if should_stop():
                stats["aborted"] = True
                break
            stats["files_total"] += 1
            name = info.filename
            if (info.is_dir() or name.lower().endswith(SKIP_EXTENSIONS)
                    or info.file_size > MAX_FILE_SIZE):
                stats["files_skipped"] += 1
                continue

            raw = apk.read(name)
            stats["files_scanned"] += 1

            if name == "AndroidManifest.xml" and raw.startswith(BINARY_XML_MAGIC):
                findings.append({
                    "rule_id": "INFO001", "title": "Binary AndroidManifest.xml "
                    "(decode with apktool to check manifest flags)",
                    "severity": "INFO", "category": "storage", "file": name,
                    "line": None, "match": ""})
                continue

            text = raw.decode("latin-1") 
            for rule in RULES:
                for m in rule.pattern.finditer(text):
                    value = mask(m.group(0)) if rule.category == "secret" else m.group(0)[:80]
                    key = (name, rule.rule_id, value)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "rule_id": rule.rule_id, "title": rule.title,
                        "severity": rule.severity, "category": rule.category,
                        "file": name, "line": text.count("\n", 0, m.start()) + 1,
                        "match": value})
    return findings, stats
