import re
import json
import uuid
import secrets
from pathlib import Path

from nacl.secret import SecretBox

OUTPUT = "memurai-license.txt"
DLLPATH = "memurai-services.dll"

PATCH_SIGNATURE = "39"
SEARCH_SIGNATURE = "85 C0 0F 85 ?? ?? ?? ?? 48 8D 4D D0 E8 ?? ?? ?? ??"

KEY = bytes.fromhex("2156a0df71d71a5c1363a2b80400cc15c1f1fe7a9dee46eec116dccdbac329a9")

PAYLOAD = {
    "license_version": "1.0",
    "license_id": str(uuid.uuid4()),
    "organization_id": str(uuid.uuid4()),
    "organization": "Definitely Licensed Team",
    "created_at": "2026-09-23T12:10:05.330Z",
    "start_date": "2026-09-23T12:07:20.980Z",
    "end_date": "2099-12-31T23:59:59.999Z",
    "order_id": str(uuid.uuid4()),
    "distribution_type": "transferable",
    "production_use": "allow",
    "product": "any",
    "platform": "any",
    "shutdown_timer": 0,
    "max_hosts": 0,
    "max_instances": 0,
    "max_connections": 0,
    "max_ram": 0,
    "min_compatible_version": "8.0.0",
    "max_compatible_version": "8.99.0",
    "surplus_instance_action": "ignore",
    "surplus_instance_buffer": 2,
    "expiration_action": "ignore",
    "telemetry": "disabled",
    "edition": "Beyond Enterprise",
    "localhost_connections": "unlimited",
    "telemetry_failure_action": "ignore",
    "telemetry_failure_threshold": 86400,
    "expiration_threshold": 0
}

def patch(data, pattern_hex, patch_hex):
    pattern = b"".join(
        b"." if x in ("?", "??") else re.escape(bytes.fromhex(x))
        for x in pattern_hex.split()
    )

    match = re.search(pattern, data, re.DOTALL)
    if not match:
        return None, data

    pos = match.start()
    patch_bytes = bytes.fromhex(patch_hex)

    if pos + len(patch_bytes) > len(data):
        raise ValueError("Patch bytes out of range.")

    data = bytearray(data)
    data[pos:pos + len(patch_bytes)] = patch_bytes
    return pos, bytes(data)

if __name__ == "__main__":
    try:
        with open(DLLPATH, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("Please run this script from memurai's root directory.")
        
    pos, data = patch(data, SEARCH_SIGNATURE, PATCH_SIGNATURE)
    
    if pos == None:
        raise RuntimeError("This error may be caused by an incompatible version of memurai.")
        
    try:
        with open(DLLPATH, "wb") as f:
            f.write(data)
    except PermissionError:
        raise PermissionError("Please stop memurai before running this script.")

    plaintext = json.dumps(PAYLOAD, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(24)
    ciphertext = bytes(SecretBox(KEY).encrypt(plaintext, nonce))[24:]
    blob = nonce + ciphertext + secrets.token_bytes(64)
    lines = ["-------- BEGIN LICENSE KEY --------"]
    
    for i in range(0, len(blob), 20):
        lines.append(",".join(str(b) for b in blob[i:i + 20]) + ",")
        
    lines.append("-------- END LICENSE KEY --------")
    Path(OUTPUT).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Cracking complete! You can launch memurai now.")
    input("Enjoy reverse engineering!\n\nPress ENTER to exit...")
