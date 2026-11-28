// Fixture for engine/myelin_engine/rules/sast/swift.yaml (opengrep --test). Not compiled.
import Foundation
import CommonCrypto

func demo(data: Data, id: String, session: URLSession, challenge: URLAuthenticationChallenge, completionHandler: Handler) {
    // ruleid: nervve.swift.weak-crypto
    let d = Insecure.MD5.hash(data: data)
    // ok: nervve.swift.weak-crypto
    let s = SHA256.hash(data: data)
    // ruleid: nervve.swift.tls-trust-all
    completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    // ruleid: nervve.swift.keychain-always-accessible
    let q = [kSecAttrAccessible: kSecAttrAccessibleAlways]
    // ruleid: nervve.swift.secret-in-userdefaults
    UserDefaults.standard.set(token, forKey: "authToken")
    // ok: nervve.swift.secret-in-userdefaults
    UserDefaults.standard.set(true, forKey: "onboarded")
    // ruleid: nervve.swift.sql-injection
    sqlite3_exec(db, "SELECT * FROM users WHERE id = \(id)", nil, nil, nil)
    // ruleid: nervve.swift.cleartext-http
    let u = URL(string: "http://api.example.com/v1")
    // ok: nervve.swift.cleartext-http
    let v = URL(string: "https://api.example.com/v1")
    // ruleid: nervve.swift.uiwebview
    let w = UIWebView()
}
