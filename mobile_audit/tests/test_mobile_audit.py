"""Tests for the mobile source SAST (OWASP Mobile Top 10, Android + iOS).

Run: python -m unittest mobile_audit.tests.test_mobile_audit -v
"""
import tempfile
import unittest
from pathlib import Path

from mobile_audit import scan_code, scan_tree


def rules(findings):
    return {f.rule_id for f in findings}


_MANIFEST = '''<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:debuggable="true" android:allowBackup="true"
               android:usesCleartextTraffic="true">
    <activity android:name=".Main" android:exported="true"/>
  </application>
</manifest>'''

_ANDROID = '''
public class Insecure {
  void bad(SQLiteDatabase db, String name, String pw) {
    db.rawQuery("SELECT * FROM u WHERE n = '" + name + "'", null);   // SQLi
    getSharedPreferences("p", MODE_WORLD_READABLE);                  // world-readable
    webView.getSettings().setJavaScriptEnabled(true);
    webView.addJavascriptInterface(new Bridge(), "android");         // JS bridge
    Log.d("TAG", "user password = " + pw);                           // sensitive log
    MessageDigest.getInstance("MD5");                                // weak hash
    Cipher.getInstance("DES/ECB/PKCS5Padding");                      // weak cipher
    String apiKey = "sk_live_ABCDEFdef1234567890";                   // hardcoded secret
    SecureRandom r = new SecureRandom(); Random weak = new Random(); // weak RNG
  }
}'''

_IOS_SWIFT = '''
import Foundation
func bad() {
    UserDefaults.standard.set(password, forKey: "user_password")     // plaintext store
    let md5 = Insecure.MD5.hash(data: d)                             // weak hash
    let apiKey = "sk_live_hardcodedSecret123456"                     // secret
    let webview = UIWebView()                                        // deprecated
    session.allowsAnyHTTPSCertificate = true                        // pinning off
}'''

_PLIST = '''<?xml version="1.0"?>
<plist><dict>
  <key>NSAppTransportSecurity</key><dict>
    <key>NSAllowsArbitraryLoads</key><true/>
  </dict>
</dict></plist>'''

_SAFE_ANDROID = '''
public class Safe {
  void ok(SQLiteDatabase db, String name) {
    db.rawQuery("SELECT * FROM u WHERE n = ?", new String[]{name});   // parameterised
    MessageDigest.getInstance("SHA-256");                            // strong hash
    String key = System.getenv("API_KEY");                          // not hardcoded
    SecureRandom r = new SecureRandom();                            // CSPRNG
  }
}'''


class TestAndroid(unittest.TestCase):
    def test_manifest_misconfig(self):
        got = rules(scan_code(_MANIFEST, "AndroidManifest.xml"))
        for r in ("MA-DEBUGGABLE", "MA-CLEARTEXT", "MA-EXPORTED", "MA-BACKUP"):
            self.assertIn(r, got)

    def test_android_code_classes(self):
        got = rules(scan_code(_ANDROID, "Insecure.java"))
        for r in ("MA-SQLI", "MA-WORLD-RW", "MA-JS-BRIDGE", "MA-LOG-SENSITIVE",
                  "MA-WEAK-HASH", "MA-WEAK-CIPHER", "MA-SECRET", "MA-WEAK-RNG"):
            self.assertIn(r, got, f"{r} should be detected in the vulnerable Android code")

    def test_sqli_is_firm(self):
        f = [x for x in scan_code(_ANDROID, "Insecure.java") if x.rule_id == "MA-SQLI"][0]
        self.assertEqual(f.confidence, "firm")
        self.assertEqual(f.owasp, "M4")
        self.assertEqual(f.platform, "android")


class TestIos(unittest.TestCase):
    def test_ios_code_classes(self):
        got = rules(scan_code(_IOS_SWIFT, "Bad.swift"))
        for r in ("MA-IOS-USERDEFAULTS", "MA-WEAK-HASH", "MA-SECRET",
                  "MA-IOS-UIWEBVIEW", "MA-IOS-PINNING-OFF"):
            self.assertIn(r, got, f"{r} should be detected in the vulnerable Swift")

    def test_plist_ats_disabled(self):
        got = rules(scan_code(_PLIST, "Info.plist"))
        self.assertIn("MA-IOS-ATS", got)

    def test_ios_platform_tagged(self):
        f = [x for x in scan_code(_IOS_SWIFT, "Bad.swift") if x.rule_id == "MA-IOS-PINNING-OFF"][0]
        self.assertEqual(f.platform, "ios")
        self.assertEqual(f.owasp, "M5")


class TestPrecision(unittest.TestCase):
    def test_safe_android_no_injection_or_secret(self):
        got = rules(scan_code(_SAFE_ANDROID, "Safe.java"))
        for r in ("MA-SQLI", "MA-SECRET", "MA-WEAK-HASH", "MA-WEAK-RNG"):
            self.assertNotIn(r, got, f"{r} must not fire on the safe Android code")

    def test_secret_placeholder_ignored(self):
        code = 'String apiKey = "YOUR_API_KEY_HERE";\n'
        self.assertNotIn("MA-SECRET", rules(scan_code(code, "C.java")))


class TestTree(unittest.TestCase):
    def test_scan_tree_reads_android_and_ios(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "AndroidManifest.xml").write_text(_MANIFEST)
            (Path(d) / "Bad.swift").write_text(_IOS_SWIFT)
            (Path(d) / "build").mkdir()
            (Path(d) / "build" / "Gen.java").write_text(_ANDROID)  # skipped dir
            found = scan_tree(d)
            platforms = {f.platform for f in found}
            self.assertIn("android", platforms)
            self.assertIn("ios", platforms)
            self.assertFalse(any("build/" in f.file or "build\\" in f.file for f in found))


if __name__ == "__main__":
    unittest.main()
