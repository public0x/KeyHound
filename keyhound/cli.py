
import argparse
import os
import signal
import sys
import zipfile

from . import __version__
from .reporter import print_summary, write_report
from .scanner import scan_apk

DEFAULT_TARGET = os.path.join("samples", "demo.apk")

BANNER = r"""
=====================================================================
 KeyHound v{ver} - Android APK secrets & insecure-storage scanner
=====================================================================
 LEGAL NOTICE
 Under the Computer Crimes Act 1997 (Malaysia), Section 3 (unauthorised
 access to computer material), Section 4 (unauthorised access with intent
 to commit further offences) and Section 5 (unauthorised modification),
 accessing or analysing systems and software without permission can be
 a criminal offence.

 Only analyse APK files that you own, or for which you hold explicit
 written authorisation. Educational use only (UniKL MIIT IKB31603).
=====================================================================
"""

_stop = False


def _handle_abort(signum, frame):
    """Kill switch: Ctrl+C stops the scan cleanly and saves a partial report."""
    global _stop
    _stop = True
    print("\n[!] Abort requested - stopping cleanly...")


def build_parser():
    p = argparse.ArgumentParser(
        prog="keyhound",
        description="Scan an Android APK for hardcoded secrets and insecure "
                    "storage indicators using static pattern matching.",
        epilog="examples:\n"
               "  python -m keyhound                       scan bundled demo APK (safe default)\n"
               "  python -m keyhound my_app.apk            scan your own APK\n"
               "  python -m keyhound my_app.apk --dry-run  validate input only\n"
               "  python -m keyhound my_app.apk -o results output to custom directory\n"
               "\nPress Ctrl+C at any time to abort safely.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("apk", nargs="?", default=DEFAULT_TARGET,
                   help=f"APK file to scan (default: {DEFAULT_TARGET})")
    p.add_argument("-o", "--output", default="output",
                   help="local output directory for the JSON report (default: output)")
    p.add_argument("--dry-run", action="store_true",
                   help="validate the APK and show the scope, but do not scan")
    p.add_argument("--version", action="version", version=f"KeyHound {__version__}")
    return p


def confirm_authorisation(target):
    print(BANNER.format(ver=__version__))
    print(f"Declared scope (file to be analysed): {target}\n")
    try:
        answer = input("Do you have authorisation to analyse this APK? (yes/no): ")
    except (KeyboardInterrupt, EOFError):
        print("\nAborted before authorisation. Exiting without scanning.")
        sys.exit(1)
    if answer.strip().lower() != "yes":
        print("Authorisation not confirmed. Exiting without scanning.")
        sys.exit(1)


def main(argv=None):
    args = build_parser().parse_args(argv)    
    confirm_authorisation(args.apk)
    signal.signal(signal.SIGINT, _handle_abort)

    if not os.path.isfile(args.apk) or not zipfile.is_zipfile(args.apk):
        print(f"[x] '{args.apk}' is not a valid APK/ZIP file.")
        return 2

    if args.dry_run:
        print("[dry-run] APK is valid and in scope. No scan performed.")
        return 0

    print(f"[*] Scanning {args.apk} (read-only, in memory) ...")
    findings, stats = scan_apk(args.apk, should_stop=lambda: _stop)
    print_summary(findings)
    report = write_report(args.apk, findings, stats, args.output)
    print(f"\n[+] Files scanned: {stats['files_scanned']}/{stats['files_total']}"
          f"{'  (ABORTED - partial results)' if stats['aborted'] else ''}")
    print(f"[+] Report saved locally: {report}")
    return 130 if stats["aborted"] else 0
