#!/usr/bin/env python3
"""Probe Apple GSA login response for debugging securityUpgrade / no-2FA accounts."""
import hashlib, hmac, json, plistlib, uuid, requests, sys
import srp._pysrp as srp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

srp.rfc5054_enable()
srp.no_username_in_x()
requests.packages.urllib3.disable_warnings()

USER_ID = uuid.uuid4()
DEVICE_ID = uuid.uuid4()
ANISETTE_URL = "https://ani.sidestore.io"

def anisette():
    h = requests.get(ANISETTE_URL, timeout=15).json()
    return {
        "X-Apple-I-MD": h["X-Apple-I-MD"],
        "X-Apple-I-MD-M": h["X-Apple-I-MD-M"],
        "X-Apple-I-MD-LU": h.get("X-Apple-I-MD-LU", ""),
        "X-Apple-I-MD-RINFO": h.get("X-Apple-I-MD-RINFO", "17106176"),
        "X-Mme-Device-Id": h.get("X-Mme-Device-Id", str(DEVICE_ID).upper()),
        "X-Apple-I-SRL-NO": h.get("X-Apple-I-SRL-NO", "0"),
    }

def cpd():
    d = {"bootstrap": True, "icscrec": True, "pbe": False, "prkgen": True, "svct": "iCloud"}
    d.update(anisette())
    return d

def gsa_req(params):
    body = {"Header": {"Version": "1.0.1"}, "Request": {"cpd": cpd(), **params}}
    r = requests.post(
        "https://gsa.apple.com/grandslam/GsService2",
        headers={
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        },
        data=plistlib.dumps(body),
        timeout=30,
        verify=False,
    )
    r.raise_for_status()
    return plistlib.loads(r.content)["Response"]

def encrypt_password(password, salt, iterations):
    p = hashlib.sha256(password.encode()).digest()
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, dklen=32)

def session_key(usr, name):
    return hmac.new(usr.get_session_key(), name.encode(), hashlib.sha256).digest()

def decrypt_cbc(usr, data):
    key = session_key(usr, "extra data key:")
    iv = session_key(usr, "extra data iv:")[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    data = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def login(username, password):
    usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    _, A = usr.start_authentication()
    r = gsa_req({"A2k": A, "ps": ["s2k", "s2k_fo"], "u": username, "o": "init"})
    if r.get("sp") != "s2k":
        print("unexpected sp", r.get("sp"))
        return
    usr.p = encrypt_password(password, r["s"], r["i"])
    M = usr.process_challenge(r["s"], r["B"])
    if M is None:
        print("challenge failed")
        return
    r = gsa_req({"c": r["c"], "M1": M, "u": username, "o": "complete"})
    usr.verify_session(r["M2"])
    spd_raw = decrypt_cbc(usr, r["spd"])
    try:
        spd = plistlib.loads(spd_raw)
    except Exception:
        PLISTHEADER = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
"""
        PLISTFOOTER = b"</plist>"
        spd = plistlib.loads(PLISTHEADER + spd_raw + PLISTFOOTER)

    status = r.get("Status", {})
    print("=== Status ===")
    print(json.dumps({k: str(v) for k, v in status.items()}, indent=2))
    print("=== Response keys ===", list(r.keys()))
    print("=== SPD keys ===", list(spd.keys()))
    if "t" in spd:
        print("=== Tokens in SPD t ===")
        for k, v in spd["t"].items():
            if isinstance(v, dict) and "token" in v:
                tok = v["token"]
                print(f"  {k}: {tok[:20]}... (len {len(tok)})")
            else:
                print(f"  {k}: {type(v)}")
    if "url" in spd:
        print("=== SPD url ===", spd["url"])
    au = status.get("au")
    print("=== au ===", au)
    return r, spd, status

if __name__ == "__main__":
    u = sys.argv[1] if len(sys.argv) > 1 else "ugaz43df34@gmail.com"
    p = sys.argv[2] if len(sys.argv) > 2 else "Chekan38629"
    login(u, p)
