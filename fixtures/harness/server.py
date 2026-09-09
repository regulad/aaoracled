#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2>=5.6", "cryptography>=42"]
# ///
"""
Oracled — minimal App Attest relying-party (RP) harness.

Role: the "server" side of App Attest. It hands out challenges, then validates
attestation objects (from DCAppAttestService.attestKey) and assertions (from
generateAssertion) against Apple's App Attest Root CA.

Design note for this project (see AGENTS.md):
  * It is STRICT on the parts that prove a genuine Secure-Enclave key + freshness:
    x5c chain to Apple's root, the credCert nonce, and keyId == SHA256(pubkey).
  * It is OBSERVATIONAL on app identity: it reports the rpIdHash and aaguid it
    sees and compares them to a table of known candidate App IDs (rows A-E),
    rather than hard-rejecting. That is exactly the RP-side "detection, not
    prevention" behaviour the M3.5 matrix needs to characterise.

Run:  uv run fixtures/harness/server.py       (uv resolves the deps above)
      python fixtures/harness/server.py       (if cbor2 + cryptography installed)

Device reaches this via an SSH *reverse* tunnel:
      ssh -R 8080:127.0.0.1:8080 <device-alias>
  then App A POSTs to http://127.0.0.1:8080 on the device.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
HOST = os.environ.get("ORACLED_HOST", "127.0.0.1")
PORT = int(os.environ.get("ORACLED_PORT", "8080"))
TEAM_ID = os.environ.get("ORACLED_TEAM_ID", "67QDNMUGFA")
# Expected App ID for the *baseline* (Row A). Everything else is reported, not required.
EXPECTED_APP_ID = os.environ.get("ORACLED_APP_ID", f"{TEAM_ID}.xyz.regulad.oracled.appone")
ENVIRONMENT = os.environ.get("ORACLED_ENV", "development")  # development|production

ROOT_CA_PATH = Path(__file__).with_name("Apple_App_Attestation_Root_CA.pem")

# AAGUID magic strings baked into authData.
AAGUID_DEV = b"appattestdevelop"                       # 16 bytes exactly
AAGUID_PROD = b"appattest" + b"\x00" * 7               # "appattest" padded to 16
NONCE_OID = "1.2.840.113635.100.8.2"                    # credCert nonce extension

# Known candidate App IDs for the M3.5 matrix — so the harness can name which
# identity an observed rpIdHash corresponds to, even on a forged/cross case.
CANDIDATE_APP_IDS = [
    f"{TEAM_ID}.xyz.regulad.oracled.appone",    # A
    f"{TEAM_ID}.xyz.regulad.oracled.apptwo",    # B
    f"{TEAM_ID}.xyz.regulad.oracled.appthree",  # C
    f"{TEAM_ID}.xyz.regulad.oracled.appfour",   # D
    # Row E's fake identity is loaded from artifacts/appE_fake_identity.txt if present.
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("oracled.harness")


def _load_row_e() -> None:
    p = Path(__file__).resolve().parents[2] / "artifacts" / "appE_fake_identity.txt"
    try:
        for line in p.read_text().splitlines():
            if line.startswith("APP_ID_STRING="):
                CANDIDATE_APP_IDS.append(line.split("=", 1)[1].strip())
    except OSError:
        pass


def rpid_hash(app_id: str) -> bytes:
    return hashlib.sha256(app_id.encode()).digest()


RPID_TABLE = {}  # hex rpIdHash -> app_id label


def _build_rpid_table() -> None:
    _load_row_e()
    for app_id in CANDIDATE_APP_IDS:
        RPID_TABLE[rpid_hash(app_id).hex()] = app_id


# ----------------------------------------------------------------------------
# State (in-memory, not persisted)
# ----------------------------------------------------------------------------
CHALLENGES: dict[str, float] = {}      # challenge_b64 -> issued_at
KEYS: dict[str, dict] = {}             # keyId_b64 -> {pub_pem, counter, app_id, ...}
CHALLENGE_TTL = 300.0
KEYS_STATE = Path(__file__).with_name("keys_state.json")


def load_keys() -> None:
    try:
        KEYS.update(json.loads(KEYS_STATE.read_text()))
        log.info("loaded %d persisted key(s)", len(KEYS))
    except (OSError, json.JSONDecodeError):
        pass


def save_keys() -> None:
    try:
        KEYS_STATE.write_text(json.dumps(KEYS, indent=2))
    except OSError:
        pass


def new_challenge() -> str:
    c = base64.b64encode(secrets.token_bytes(32)).decode()
    CHALLENGES[c] = time.time()
    return c


def take_challenge(c: str) -> bool:
    ts = CHALLENGES.pop(c, None)
    return ts is not None and (time.time() - ts) <= CHALLENGE_TTL


# ----------------------------------------------------------------------------
# Minimal DER helper to pull the nonce out of the credCert extension.
# Structure: SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
# ----------------------------------------------------------------------------
def extract_nonce_from_extension(der: bytes) -> bytes:
    # Walk TLVs looking for the innermost 32-byte OCTET STRING (tag 0x04).
    def walk(b: bytes):
        i = 0
        while i < len(b):
            tag = b[i]; i += 1
            if i >= len(b):
                break
            length = b[i]; i += 1
            if length & 0x80:
                n = length & 0x7F
                length = int.from_bytes(b[i:i + n], "big"); i += n
            val = b[i:i + length]; i += length
            yield tag, val
            if tag & 0x20:  # constructed -> recurse
                yield from walk(val)
    for tag, val in walk(der):
        if tag == 0x04 and len(val) == 32:
            return val
    raise ValueError("nonce OCTET STRING not found in credCert extension")


# ----------------------------------------------------------------------------
# Attestation validation
# ----------------------------------------------------------------------------
def load_root() -> x509.Certificate:
    return x509.load_pem_x509_certificate(ROOT_CA_PATH.read_bytes())


ROOT = load_root()


def verify_cert_chain(x5c: list[bytes]) -> tuple[bool, x509.Certificate, str]:
    """x5c = [credCert(leaf), intermediate]. Verify leaf<-intermediate<-ROOT."""
    try:
        leaf = x509.load_der_x509_certificate(x5c[0])
        inter = x509.load_der_x509_certificate(x5c[1])
        # intermediate signed by root
        ROOT.public_key().verify(
            inter.signature, inter.tbs_certificate_bytes,
            ec.ECDSA(inter.signature_hash_algorithm),
        )
        # leaf signed by intermediate
        inter.public_key().verify(
            leaf.signature, leaf.tbs_certificate_bytes,
            ec.ECDSA(leaf.signature_hash_algorithm),
        )
        return True, leaf, "chain to Apple App Attest Root CA OK"
    except (InvalidSignature, ValueError, IndexError) as e:
        # still return leaf if we could parse it, for observability
        try:
            leaf = x509.load_der_x509_certificate(x5c[0])
        except Exception:
            leaf = None
        return False, leaf, f"chain FAILED: {e}"


def parse_auth_data(auth_data: bytes) -> dict:
    rp_id_hash = auth_data[0:32]
    flags = auth_data[32]
    counter = int.from_bytes(auth_data[33:37], "big")
    aaguid = auth_data[37:53]
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    cred_id = auth_data[55:55 + cred_id_len]
    return {
        "rp_id_hash": rp_id_hash,
        "flags": flags,
        "counter": counter,
        "aaguid": aaguid,
        "cred_id": cred_id,
    }


def uncompressed_point(pub: ec.EllipticCurvePublicKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def validate_attestation(key_id_b64: str, att_obj: bytes, challenge_b64: str) -> dict:
    report: dict = {"ok": False, "checks": {}, "observed": {}}
    ch = report["checks"]

    obj = cbor2.loads(att_obj)
    fmt = obj.get("fmt")
    att_stmt = obj.get("attStmt", {})
    auth_data = obj.get("authData")
    ch["fmt_is_apple_appattest"] = (fmt == "apple-appattest")

    x5c = att_stmt.get("x5c", [])
    chain_ok, leaf, chain_msg = verify_cert_chain(x5c)
    ch["cert_chain"] = {"ok": chain_ok, "msg": chain_msg}

    # nonce: SHA256(authData || clientDataHash), clientDataHash = SHA256(challenge)
    challenge = base64.b64decode(challenge_b64)
    client_data_hash = hashlib.sha256(challenge).digest()
    computed_nonce = hashlib.sha256(auth_data + client_data_hash).digest()
    nonce_ok = False
    if leaf is not None:
        try:
            ext = leaf.extensions.get_extension_for_oid(x509.ObjectIdentifier(NONCE_OID))
            cert_nonce = extract_nonce_from_extension(ext.value.value)
            nonce_ok = secrets.compare_digest(cert_nonce, computed_nonce)
            ch["nonce"] = {"ok": nonce_ok}
        except Exception as e:
            ch["nonce"] = {"ok": False, "msg": str(e)}
    else:
        ch["nonce"] = {"ok": False, "msg": "no leaf cert"}

    ad = parse_auth_data(auth_data)
    key_id = base64.b64decode(key_id_b64)

    # keyId == SHA256(public key uncompressed point); also cred_id == keyId
    pub = leaf.public_key() if leaf is not None else None
    key_id_ok = False
    if isinstance(pub, ec.EllipticCurvePublicKey):
        pk_hash = hashlib.sha256(uncompressed_point(pub)).digest()
        key_id_ok = secrets.compare_digest(pk_hash, key_id)
    ch["key_id_matches_pubkey"] = key_id_ok
    ch["cred_id_matches_key_id"] = secrets.compare_digest(ad["cred_id"], key_id)

    ch["counter_is_zero"] = (ad["counter"] == 0)

    # aaguid / environment
    aaguid = ad["aaguid"]
    env = ("development" if aaguid == AAGUID_DEV
           else "production" if aaguid == AAGUID_PROD else "unknown")
    ch["environment_matches"] = (env == ENVIRONMENT)
    report["observed"]["aaguid"] = aaguid.rstrip(b"\x00").decode("latin1")
    report["observed"]["environment"] = env
    report["observed"]["counter"] = ad["counter"]

    # rpIdHash — OBSERVATIONAL: report which known App ID it corresponds to.
    rp_hex = ad["rp_id_hash"].hex()
    identified = RPID_TABLE.get(rp_hex)
    report["observed"]["rp_id_hash"] = rp_hex
    report["observed"]["app_id"] = identified or "UNKNOWN (matches no candidate)"
    report["observed"]["rp_id_hash_matches_expected"] = (
        rp_hex == rpid_hash(EXPECTED_APP_ID).hex()
    )

    genuine = chain_ok and nonce_ok and key_id_ok and ch["cred_id_matches_key_id"]
    report["ok"] = genuine
    report["genuine_sep_key"] = genuine  # explicit: this proves a real SEP key + freshness

    if genuine and isinstance(pub, ec.EllipticCurvePublicKey):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
        KEYS[key_id_b64] = {
            "pub_pem": pem, "counter": ad["counter"],
            "app_id": report["observed"]["app_id"], "rp_id_hash": rp_hex,
            "stored_at": time.time(),
        }
        save_keys()
    return report


def validate_assertion(key_id_b64: str, assertion: bytes, challenge_b64: str) -> dict:
    report: dict = {"ok": False, "checks": {}, "observed": {}}
    ch = report["checks"]
    rec = KEYS.get(key_id_b64)
    if rec is None:
        report["error"] = "unknown keyId (attest first)"
        return report

    obj = cbor2.loads(assertion)
    signature = obj["signature"]
    auth_data = obj["authenticatorData"]

    challenge = base64.b64decode(challenge_b64)
    client_data_hash = hashlib.sha256(challenge).digest()
    composite = auth_data + client_data_hash
    nonce = hashlib.sha256(composite).digest()

    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pub = load_pem_public_key(rec["pub_pem"].encode())

    # Apple's docs are ambiguous about the exact digest the SEP signs. Try the
    # candidate conventions and record which verifies, so we lock it in.
    methods = {
        # ECDSA-SHA256 over (authenticatorData || clientDataHash): single hash.
        "ecdsa_sha256_over_composite": (composite, ec.ECDSA(hashes.SHA256())),
        # signature over the 32-byte nonce treated as a pre-computed digest.
        "prehashed_nonce": (nonce, ec.ECDSA(Prehashed(hashes.SHA256()))),
        # ECDSA-SHA256 over the nonce (i.e. double hash SHA256(nonce)).
        "ecdsa_sha256_over_nonce": (nonce, ec.ECDSA(hashes.SHA256())),
    }
    passed = None
    for name, (msg, algo) in methods.items():
        try:
            pub.verify(signature, msg, algo)
            passed = name
            break
        except InvalidSignature:
            continue
    ch["signature"] = passed is not None
    ch["signature_method"] = passed

    ad = parse_auth_data(auth_data + b"\x00" * 20)  # assertion authData has no cred; pad for parser
    prev = rec["counter"]
    ch["counter_increased"] = ad["counter"] > prev
    ch["rp_id_hash_matches"] = (ad["rp_id_hash"].hex() == rec["rp_id_hash"])
    report["observed"]["counter"] = ad["counter"]
    report["observed"]["prev_counter"] = prev

    # Dump raw inputs so the convention can be nailed offline without relaunching.
    try:
        dbg = Path(__file__).with_name("last_assertion.json")
        dbg.write_text(json.dumps({
            "assertion_b64": base64.b64encode(assertion).decode(),
            "challenge_b64": challenge_b64,
            "authenticatorData_hex": auth_data.hex(),
            "signature_hex": signature.hex(),
            "pub_pem": rec["pub_pem"],
            "computed_nonce_hex": nonce.hex(),
            "signature_method": passed,
        }, indent=2))
    except OSError:
        pass

    if ch["signature"] and ch["counter_increased"]:
        rec["counter"] = ad["counter"]
        save_keys()
        report["ok"] = True
    return report


# ----------------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "oracled-harness/0.1"

    def _send(self, code: int, obj: dict):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        n = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path.startswith("/challenge"):
            c = new_challenge()
            log.info("issued challenge %s", c[:12] + "...")
            self._send(200, {"challenge": c})
        elif self.path.startswith("/keys"):
            self._send(200, {k: {kk: vv for kk, vv in v.items() if kk != "pub_pem"}
                             for k, v in KEYS.items()})
        elif self.path.startswith("/health"):
            self._send(200, {"ok": True, "expected_app_id": EXPECTED_APP_ID,
                             "environment": ENVIRONMENT})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            data = self._read_json()
            if self.path.startswith("/attest"):
                if not take_challenge(data["challenge"]):
                    self._send(400, {"error": "unknown/expired challenge"}); return
                rep = validate_attestation(
                    data["keyId"], base64.b64decode(data["attestation"]), data["challenge"])
                log.info("ATTEST keyId=%s genuine=%s app_id=%s rp_match=%s",
                         data["keyId"][:12] + "...", rep["ok"],
                         rep["observed"].get("app_id"),
                         rep["observed"].get("rp_id_hash_matches_expected"))
                self._send(200, rep)
            elif self.path.startswith("/assert"):
                if not take_challenge(data["challenge"]):
                    self._send(400, {"error": "unknown/expired challenge"}); return
                rep = validate_assertion(
                    data["keyId"], base64.b64decode(data["assertion"]), data["challenge"])
                log.info("ASSERT keyId=%s ok=%s counter=%s",
                         data["keyId"][:12] + "...", rep["ok"],
                         rep["observed"].get("counter"))
                self._send(200, rep)
            else:
                self._send(404, {"error": "not found"})
        except Exception as e:  # surface the error to the client/log
            log.exception("request failed")
            self._send(500, {"error": repr(e)})

    def log_message(self, *_):  # quiet default access log; we log our own lines
        pass


def main():
    _build_rpid_table()
    load_keys()
    log.info("Apple App Attest Root CA loaded: %s",
             ROOT.subject.rfc4514_string())
    log.info("expected baseline App ID: %s (env=%s)", EXPECTED_APP_ID, ENVIRONMENT)
    log.info("known rpIdHash candidates: %d", len(RPID_TABLE))
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    log.info("listening on http://%s:%d  (device: ssh -R %d:127.0.0.1:%d <device-alias>)",
             HOST, PORT, PORT, PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
