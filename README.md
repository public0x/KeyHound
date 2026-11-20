# KeyHound

**A simple static scanner that finds hardcoded secrets and insecure-storage indicators in Android APK files.**

- **Attack category:** Mobile Application Attack (insecure storage detector / secret key scanner)
- **Course:** Ethical Hacking (IKB31603), UniKL MIIT, October 2026
- **Language:** Python 3.8+ (standard library only)
- **Version:** 1.0.0

---

## Table of Contents
1. [Description](#description)
2. [Attack Lifecycle Mapping](#attack-lifecycle-mapping)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Sample Output](#sample-output)
6. [Detection Rules](#detection-rules)
7. [Ethical Considerations](#ethical-considerations)
8. [Rules of Engagement (RoE)](#rules-of-engagement-roe)
9. [Responsible Disclosure](#responsible-disclosure)
10. [Legal Disclaimer](#legal-disclaimer)
11. [Limitations](#limitations)
12. [Project Structure](#project-structure)
13. [Contributors and License](#contributors-and-license)

---

## Description

Mobile developers often leave API keys, tokens, private keys and passwords inside their apps, or store data in ways other apps can read (world-readable files, external storage, backups enabled). Because an APK is just a ZIP archive, these mistakes can be found without running the app.

KeyHound opens an APK **read-only and in memory**, walks through every file inside it, and applies a set of regular-expression rules. It reports:

- **Hardcoded secrets:** AWS keys, Google API keys, private key blocks, JWTs, Firebase URLs, credential assignments, secrets in string resources.
- **Insecure storage indicators:** `MODE_WORLD_READABLE/WRITEABLE`, external storage use, raw SQLite use, `SharedPreferences` use, `allowBackup="true"`, `debuggable="true"`, cleartext `http://` URLs.

Findings are printed as a severity-sorted table and saved as a JSON report in a local `output/` folder. Secret values are **masked** (for example `AKIA******LE`) so the report never contains full credentials.

## Attack Lifecycle Mapping

| Lifecycle stage | What KeyHound does |
|---|---|
| **1. Reconnaissance** | Opens the target APK and enumerates its internal files (manifest, resources, assets, `classes.dex`). |
| **2. Scanning / Enumeration** | Applies 14 regex rules across all text-readable entries and records file name, line number and rule ID. |
| **3. Vulnerability Analysis** | Classifies each match by severity (HIGH / MEDIUM / LOW) and category (secret / storage). |
| **4. Exploitation (assessment only)** | **Deliberately not performed.** The tool identifies where a real attacker could extract keys or read data, but never uses or validates a credential. |
| **5. Reporting** | Prints a summary and writes a labelled local JSON report with masked values. |

```
 APK file --> [open read-only] --> [enumerate files] --> [regex rules]
                                                              |
                                  JSON report  <-- [classify severity]
```

## Installation

```bash
git clone https://github.com/public0x/KeyHound.git
cd keyhound
python3 -m venv venv && source venv/bin/activate    # optional
pip install -r requirements.txt                     # no external packages needed
```

Rebuild the bundled demo target at any time:

```bash
python3 tools/make_demo_apk.py
```

## Usage

```bash
python -m apkscan                        # scan bundled demo APK (safe default)
python -m apkscan my_app.apk             # scan your own APK
python -m apkscan my_app.apk --dry-run   # validate input and scope only
python -m apkscan my_app.apk -o results  # custom output directory
python -m apkscan --help                 # full help with examples
```

On startup the tool shows the legal notice and requires you to type `yes` to confirm authorisation. Anything else exits without scanning. Press **Ctrl+C** at any time to stop safely (a partial report is still saved).

Run the tests:

```bash
python -m unittest discover -s tests -v
```

## Sample Output

```
SEV      ID      FILE                               FINDING
------------------------------------------------------------------------------------------
HIGH     STO006  AndroidManifest.xml                Debuggable build (android:debuggable=true)
HIGH     SEC001  assets/config.json                 AWS Access Key ID
HIGH     SEC002  assets/google_services.txt         Google API key
HIGH     SEC003  assets/id_rsa_demo.pem             Private key block
HIGH     STO001  classes.dex                        World-readable/writable file mode
MEDIUM   STO005  AndroidManifest.xml                Backup allowed (android:allowBackup=true)
...
Totals: HIGH=5  MEDIUM=6  LOW=4  INFO=0
[+] Report saved locally: output/apkscan_report_<timestamp>.json
```



## Detection Rules

| ID | Finding | Severity |
|---|---|---|
| SEC001 | AWS Access Key ID | HIGH |
| SEC002 | Google API key | HIGH |
| SEC003 | Private key block | HIGH |
| SEC004 | Hardcoded credential assignment | MEDIUM |
| SEC005 | JSON Web Token | MEDIUM |
| SEC006 | Firebase database URL | LOW |
| SEC007 | Secret in Android string resource | MEDIUM |
| STO001 | World-readable/writable file mode | HIGH |
| STO002 | External storage usage | LOW |
| STO003 | Raw SQLite database usage | MEDIUM |
| STO004 | SharedPreferences usage | LOW |
| STO005 | `allowBackup="true"` | MEDIUM |
| STO006 | `debuggable="true"` | HIGH |
| STO007 | Cleartext HTTP URL | LOW |

## Ethical Considerations

| Guardrail | Implementation | Reason |
|---|---|---|
| Authorisation prompt | Startup banner + typed `yes` confirmation | Makes the user consciously accept responsibility. |
| Scope declaration | The target file is displayed as the declared scope before scanning | Keeps the scan limited to one authorised file. |
| Safe default | Default target is the bundled fake `samples/demo.apk` | An accidental run can only touch harmless test data. |
| Dry-run | `--dry-run` validates without scanning | Lets users confirm scope safely. |
| Kill switch | Ctrl+C sets a stop flag; scan ends cleanly | Allows immediate, safe abort. |
| Passive only | No network access, no app execution, no credential validation | Avoids any impact on live systems. |
| Data minimisation | Nothing extracted to disk; secrets masked; no upload | Avoids creating new copies of sensitive data. |
| Local labelled output | Reports go only to `output/` and are git-ignored | Prevents accidental publication of findings. |
| Resource safety | Entries over 10 MB are skipped | Guards against oversized/zip-bomb entries. |

## Rules of Engagement (RoE)

**Authorised scope**
- Only APK files that you own, that your team developed, or that the owner has authorised **in writing** for analysis.
- The bundled `samples/demo.apk` (fake data) is always in scope.
- Course use: APKs provided or approved by the lecturer.

**Time windows**
- Scanning only within the authorised testing period stated in the written permission (for coursework: the Oct 2026 semester lab/assessment period).
- No scanning outside agreed windows. If no window is defined, obtain one before scanning.

**Permitted techniques**
- Static, read-only analysis of the APK file with this tool.
- Reviewing and reporting the findings to the app owner.

**Prohibited actions**
- Scanning APKs without authorisation, or APKs belonging to third parties.
- Using, testing or logging in with any discovered credential or key.
- Sharing, publishing or uploading unmasked secrets or the full report.
- Modifying the tool to exfiltrate data or to attack running systems.
- Any use that violates the Computer Crimes Act 1997 or UniKL policy.

**Emergency stop procedure**
1. Press **Ctrl+C** to stop the scan (partial report saved).
2. If the terminal is unresponsive, close it or kill the process (`kill <pid>`).
3. If you believe you scanned something out of scope: stop, delete the report in `output/`, and inform your lecturer and the file owner immediately.

## Responsible Disclosure

If you find a real secret or storage weakness in an app you were authorised to test:

- **Who:** the app owner or vendor security contact (for example `security@` address or their bug bounty / vulnerability disclosure page). For coursework, your lecturer.
- **When:** report as soon as possible, ideally within **24-48 hours** of confirming the finding. Allow a reasonable fix period (commonly **90 days**) before any public discussion, and only publish with the owner's consent.
- **How:** send a private, encrypted channel if possible. Include the app name/version, affected file, rule ID and severity, and remediation advice (for example revoke and rotate the key, move secrets to a server or Android Keystore, disable `allowBackup`, use `MODE_PRIVATE` and encrypted storage). **Never include full secrets**; use the masked values from the report.
- **After reporting:** delete local reports once the issue is resolved or no longer needed.
- Do not exploit, test or share the discovered credential at any time.

## Legal Disclaimer

This tool is for **educational purposes and authorised security testing only**. In Malaysia, the **Computer Crimes Act 1997** makes unauthorised access to computer material (Section 3), unauthorised access with intent to commit further offences (Section 4) and unauthorised modification (Section 5) criminal offences. The authors accept no responsibility for misuse. By using this tool you confirm that you hold explicit authorisation for the APK you analyse.

## Limitations

- Static regex matching only: it can produce **false positives** (placeholder keys) and **false negatives** (obfuscated, encrypted or split secrets).
- Compiled `AndroidManifest.xml` and `resources.arsc` are binary; KeyHound reports that the manifest is binary but cannot read its flags. Decode with `apktool` and scan the result.
- `classes.dex` is searched as raw text, so only plain strings are visible; it is not decompiled.
- Detects indicators of insecure storage (API usage), not proof that sensitive data is actually stored insecurely.
- No entropy analysis, no native library (`.so`) analysis, no certificate pinning checks.
- Does not check for any of the data after install (no device or emulator inspection).

## Project Structure

```
keyhound/
├── keyhound/            # package: cli, scanner, rules, reporter
├── samples/demo.apk    # safe default target (fake data)
├── tools/make_demo_apk.py
├── tests/test_scanner.py
├── README.md  LICENSE  .gitignore  requirements.txt
```

## Contributors and License

Team members: MUHAMMAD AMMAR BIN ADI HARRIZAM (5222610088), MUHAMMAD HATIM BIN HASNUL. Released under the **MIT License** (see `LICENSE`).
