# Copyright (c) 2026 Sudheer Kumar.
# SPDX-License-Identifier: AGPL-3.0-only. See LICENSE.
"""Cryptography inventory (CBOM) and post-quantum readiness.

Finds where first-party code uses cryptographic algorithms and protocols, classifies each one, and exports the
inventory as a CycloneDX 1.6 Cryptography Bill of Materials:

  broken              no longer acceptable today (MD5, SHA-1 signatures, DES/3DES, RC4, ECB mode, TLS 1.0/1.1)
  quantum-vulnerable  public-key cryptography a large quantum computer breaks (RSA, ECDSA/ECDH, DH, DSA, Ed25519/X25519);
                      plan migration to ML-KEM (FIPS 203) and ML-DSA (FIPS 204) or hybrid schemes
  quantum-safe        symmetric and hash primitives at adequate strength, and NIST post-quantum algorithms
  review              strength depends on parameters the code does not show (e.g. AES key size)

The inventory is evidence for planning, not a vulnerability list: broken algorithms are already reported as
findings by the code engine; quantum-vulnerable use is a migration item.
"""
import os
import re
import uuid
from datetime import datetime, timezone

CODE_EXT = (".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".java", ".kt", ".go", ".cs", ".php", ".rb", ".rs",
            ".yaml", ".yml", ".conf", ".properties", ".toml", ".json")
SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "vendor", ".tox", "tests", "test",
        "__tests__", "spec", "testdata", "fixtures"}

# algorithm -> (family, CycloneDX primitive, classification, NIST quantum security level, patterns)
ALGORITHMS = [
    ("ML-KEM", "ML-KEM", "kem", "quantum-safe", 3,
     r"(?i)\b(ml[-_]?kem|kyber(512|768|1024)?|mlkem\d*|X25519MLKEM768)\b"),
    ("ML-DSA", "ML-DSA", "signature", "quantum-safe", 3,
     r"(?i)\b(ml[-_]?dsa|dilithium[235]?|mldsa\d*)\b"),
    ("SLH-DSA", "SLH-DSA", "signature", "quantum-safe", 1, r"(?i)\b(slh[-_]?dsa|sphincs\+?)\b"),
    ("RSA", "RSA", "pke", "quantum-vulnerable", 0,
     r"\brsa\.generate_private_key\b|\bRSA\.(generate|import_key|importKey|Create)\b|getInstance\(\s*\"RSA|\brsa\.GenerateKey\b|"
     r"generateKeyPair(Sync)?\(\s*['\"]rsa|\bRSACryptoServiceProvider\b|OpenSSL::PKey::RSA|\bPKCS1_(OAEP|v1_5)\b|"
     r"['\"](RS|PS)(256|384|512)['\"]|\bRsaKeyPairGenerator\b|OPENSSL_KEYTYPE_RSA"),
    ("ECDSA/ECDH", "EC", "signature", "quantum-vulnerable", 0,
     r"\bec\.generate_private_key\b|\bec\.(SECP256R1|SECP384R1|SECP521R1|ECDH)\b|getInstance\(\s*\"(EC|ECDSA|ECDH)\"|"
     r"\becdsa\.(GenerateKey|Sign)\b|\belliptic\.P(256|384|521)\(|generateKeyPair(Sync)?\(\s*['\"]ec['\"]|\bECDsa\.Create\b|"
     r"\bECDiffieHellman\b|createECDH\(|['\"]ES(256|384|512)['\"]|\bsecp256k1\b"),
    ("Ed25519/X25519", "EdDSA", "signature", "quantum-vulnerable", 0,
     r"\b(Ed25519|X25519|Ed448|X448)(PrivateKey|PublicKey)?\b|\bed25519\.(GenerateKey|Sign)\b|generateKeyPair(Sync)?\(\s*['\"](ed25519|x25519)"),
    ("Diffie-Hellman", "DH", "key-agree", "quantum-vulnerable", 0,
     r"\bdh\.generate_parameters\b|createDiffieHellman(Group)?\(|getInstance\(\s*\"DH\"|\bDiffieHellman\b"),
    ("DSA", "DSA", "signature", "quantum-vulnerable", 0,
     r"\bdsa\.generate_private_key\b|getInstance\(\s*\"DSA\"|\bDSACryptoServiceProvider\b|\bdsa\.GenerateKey\b"),
    ("AES-GCM", "AES", "ae", "quantum-safe", 1,
     r"\bAESGCM\b|AES\.MODE_GCM|['\"]aes-(128|192|256)-gcm['\"]|AES/GCM|cipher\.NewGCM\(|\bAesGcm\b"),
    ("AES-ECB", "AES", "block-cipher", "broken", 0,
     r"AES\.MODE_ECB|modes\.ECB\(|['\"]aes-(128|192|256)-ecb['\"]|AES/ECB|CipherMode\.ECB"),
    ("AES", "AES", "block-cipher", "review", 1,
     r"\bAES\.new\(|algorithms\.AES\(|getInstance\(\s*\"AES[\"/]|\baes\.NewCipher\(|createCipheriv\(\s*['\"]aes-(128|192|256)-(cbc|ctr|cfb|ofb)|"
     r"\bAes\.Create\(|openssl_encrypt\([^)]*['\"]aes-"),
    ("ChaCha20-Poly1305", "ChaCha20", "ae", "quantum-safe", 1, r"(?i)\bchacha20[-_]?poly1305\b|\bChaCha20Poly1305\b"),
    ("3DES/DES", "DES", "block-cipher", "broken", 0,
     r"\b(DES3|TripleDES|DESede)\b|algorithms\.TripleDES|getInstance\(\s*\"DES|['\"]des-(ede3?-)?cbc['\"]|\bdes\.NewCipher\b"),
    ("RC4", "RC4", "stream-cipher", "broken", 0, r"\bARC4\b|algorithms\.ARC4|['\"]rc4['\"]|getInstance\(\s*\"RC4|\brc4\.NewCipher\b"),
    ("MD5", "MD5", "hash", "broken", 0,
     r"\bhashlib\.md5\b|createHash\(\s*['\"]md5|MessageDigest\.getInstance\(\s*\"MD5|\bmd5\.(New|Sum)\b|\bMD5\.Create\(|\bmd5\(|Digest::MD5"),
    ("SHA-1", "SHA-1", "hash", "broken", 0,
     r"\bhashlib\.sha1\b|createHash\(\s*['\"]sha1|MessageDigest\.getInstance\(\s*\"SHA-?1\"|\bsha1\.(New|Sum)\b|\bSHA1\.Create\(|"
     r"\bsha1\(|Digest::SHA1|['\"]HS1['\"]"),
    ("SHA-2", "SHA-2", "hash", "quantum-safe", 2,
     r"\bhashlib\.sha(256|384|512)\b|createHash\(\s*['\"]sha(256|384|512)|getInstance\(\s*\"SHA-(256|384|512)|\bsha(256|512)\.(New|Sum)|"
     r"\bSHA(256|384|512)\.Create\(|Digest::SHA(256|384|512)"),
    ("SHA-3", "SHA-3", "hash", "quantum-safe", 2, r"\bhashlib\.sha3_(256|384|512)\b|['\"]sha3-(256|384|512)['\"]|\bsha3\.New"),
    ("HMAC-SHA256", "HMAC", "mac", "quantum-safe", 2, r"['\"]HS(256|384|512)['\"]|hmac\.new\([^)]*sha(256|384|512)|createHmac\(\s*['\"]sha(256|384|512)"),
    ("Password hashing", "KDF", "kdf", "quantum-safe", 1,
     r"\b(bcrypt\.(hashpw|hash|gensalt)|argon2|scrypt|PBKDF2HMAC|pbkdf2_hmac|pbkdf2Sync|Rfc2898DeriveBytes)\b"),
    ("TLS 1.0/1.1", "TLS", "protocol", "broken", 0,
     r"PROTOCOL_TLSv1(_1)?\b|TLSVersion\.TLSv1(_1)?\b|minVersion\s*[:=]\s*['\"]TLSv1(\.1)?['\"]|tls\.VersionTLS1[01]\b|"
     r"SslProtocols\.Tls(11)?\b|ssl_protocols[^;\n]*TLSv1(\.1)?\s"),
]
MANIFESTS = {"package.json", "package-lock.json", "composer.json", "composer.lock", "pyproject.toml", "Cargo.toml", "Cargo.lock",
             "tsconfig.json", "crypto_inventory.py"}
_COMPILED = [(a, fam, prim, cls, lvl, re.compile(rx)) for a, fam, prim, cls, lvl, rx in ALGORITHMS]
ADVICE = {
    "broken": "Replace now: use AES-GCM or ChaCha20-Poly1305 for encryption, SHA-256 or better for hashing, TLS 1.2+ (1.3 preferred).",
    "quantum-vulnerable": "Add to the post-quantum migration plan: ML-KEM (FIPS 203) for key establishment and ML-DSA (FIPS 204) "
                          "for signatures, starting with hybrid modes (e.g. X25519MLKEM768 in TLS) for data that must stay "
                          "confidential for years.",
    "quantum-safe": "No action: adequate today and against known quantum attacks (prefer 256-bit keys for long-lived data).",
    "review": "Confirm the key size: AES-256 for data that must stay confidential long-term.",
}


def scan(root: str) -> list[dict]:
    assets = {}
    for dp, dn, fns in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP]
        for fn in fns:
            if not fn.endswith(CODE_EXT) or fn.endswith(".min.js") or fn in MANIFESTS:
                continue
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace("\\", "/")
            try:
                if os.path.getsize(p) > 1_500_000:
                    continue
                lines = open(p, encoding="utf-8", errors="ignore").read().splitlines()
            except OSError:
                continue
            for i, ln in enumerate(lines, 1):
                s = ln.strip()
                if not s or s.startswith(("#", "//", "*", "/*", "--")):
                    continue
                for alg, fam, prim, cls, lvl, rx in _COMPILED:
                    if rx.search(ln):
                        a = assets.setdefault(alg, {"algorithm": alg, "family": fam, "primitive": prim, "classification": cls,
                                                     "nist_quantum_level": lvl, "advice": ADVICE[cls], "occurrences": []})
                        if len(a["occurrences"]) < 50:
                            a["occurrences"].append({"file": rel, "line": i, "snippet": s[:120]})
                        a["count"] = a.get("count", 0) + 1
                        break                              # most specific pattern first: one asset per line
    order = {"broken": 0, "quantum-vulnerable": 1, "review": 2, "quantum-safe": 3}
    return sorted(assets.values(), key=lambda a: (order[a["classification"]], -a.get("count", 0)))


def readiness(assets: list[dict]) -> dict:
    """Post-quantum readiness summary for one repository (or several: pass the concatenated inventories)."""
    by = {"broken": 0, "quantum-vulnerable": 0, "review": 0, "quantum-safe": 0}
    for a in assets:
        by[a["classification"]] += a.get("count", len(a.get("occurrences", [])))
    asym = [a for a in assets if a["primitive"] in ("pke", "signature", "kem", "key-agree")]
    pqc = sum(a.get("count", 1) for a in asym if a["classification"] == "quantum-safe")
    vuln = sum(a.get("count", 1) for a in asym if a["classification"] == "quantum-vulnerable")
    total = sum(by.values())
    score = 100 if total == 0 else round(100 * (by["quantum-safe"] + 0.5 * by["review"]) / total)
    return {"uses": total, "by_class": by, "asymmetric_uses": pqc + vuln, "pqc_asymmetric_uses": pqc,
            "pqc_share": round(100 * pqc / (pqc + vuln)) if (pqc + vuln) else None, "score": score,
            "status": "action" if by["broken"] else "plan" if vuln else "ready"}


def cbom(assets: list[dict], name: str = "application") -> dict:
    """CycloneDX 1.6 Cryptography Bill of Materials."""
    comps = []
    for a in assets:
        ref = f"crypto:algorithm:{re.sub(r'[^A-Za-z0-9]+', '-', a['algorithm']).strip('-').lower()}"
        props = {"primitive": a["primitive"], "nistQuantumSecurityLevel": a["nist_quantum_level"],
                 "cryptoFunctions": ["unknown"]}
        if a["primitive"] == "protocol":
            crypto = {"assetType": "protocol", "protocolProperties": {"type": "tls"}}
        else:
            crypto = {"assetType": "algorithm", "algorithmProperties": props}
        comps.append({
            "type": "cryptographic-asset", "bom-ref": ref, "name": a["algorithm"], "cryptoProperties": crypto,
            "evidence": {"occurrences": [{"location": o["file"], "line": o["line"]} for o in a["occurrences"][:50]]},
            "properties": [{"name": "myelin:classification", "value": a["classification"]},
                           {"name": "myelin:uses", "value": str(a.get("count", len(a["occurrences"])))}],
        })
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(),
                         "tools": {"components": [{"type": "application", "name": "NERvvE DevSecOps", "version": "1.0.0"}]},
                         "component": {"type": "application", "bom-ref": f"urn:myelin:application:{name}", "name": name},
                         "properties": [{"name": "myelin:pqc-readiness", "value": str(readiness(assets)["score"])}]},
            "components": comps}
