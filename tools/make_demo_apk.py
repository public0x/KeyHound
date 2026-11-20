"""Builds samples/demo.apk: a deliberately vulnerable, FAKE APK-shaped ZIP.

It is NOT an installable app. It only contains fake secrets and code strings so
APKScan has something safe to detect. All keys below are dummy values.
"""
import os
import zipfile

OUT = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.apk")

FILES = {
    "AndroidManifest.xml": """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.vulnerablebank">
    <application
        android:label="VulnerableBank (DEMO)"
        android:allowBackup="true"
        android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>
""",
    "res/values/strings.xml": """<resources>
    <string name="app_name">VulnerableBank</string>
    <string name="payment_api_secret">DEMO-SECRET-0123456789</string>
</resources>
""",
    "assets/config.json": """{
  "api_url": "http://api.demo-bank.example.com/v1",
  "api_key": "FAKE-API-KEY-1234567890",
  "firebase": "https://demo-bank-12345.firebaseio.com",
  "aws_access_key": "AKIAIOSFODNN7EXAMPLE"
}
""",
    "assets/google_services.txt":
        "maps_key=AIzaSyDEMO000000000000000000000000000AB\n",
    "assets/id_rsa_demo.pem":
        "-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKEFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----\n",
    "assets/session.txt":
        "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.ZmFrZXNpZ25hdHVyZTEyMzQ1\n",
    # Pretend compiled code: readable strings, as found inside real classes.dex
    "classes.dex": (
        "dex\n035\x00 com/example/vulnerablebank/Storage "
        "context.getSharedPreferences(\"user\", Context.MODE_WORLD_READABLE) "
        "Environment.getExternalStorageDirectory() "
        "db = openOrCreateDatabase(\"bank.db\", 0, null) "
        "String password = \"SuperSecret123!\"; "
    ),
}


def build():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in FILES.items():
            z.writestr(name, content)
    print(f"Built {os.path.abspath(OUT)}")


if __name__ == "__main__":
    build()
