#!/usr/bin/env python3
import csv, json, re, sys, ipaddress
from typing import Dict, Any, Optional

# Keys we care about
PHONE_KEYS = {"phone", "contact"}
UPI_KEYS = {"upi_id"}
AADHAR_KEYS = {"aadhar", "aadhaar", "address_proof"}
PASSPORT_KEYS = {"passport"}

# Regex patterns
email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}")
upi_re = re.compile(r"[\w.\-]+@[A-Za-z]{2,}")
# Strict 10-digit (standalone) capture
phone_10_re = re.compile(r"(?<!\d)(\d{10})(?!\d)")
# Aadhaar: 12 digits with optional spaces in groups of 4
aadhar_re = re.compile(r"(?<!\d)(?:\d{4}\s?\d{4}\s?\d{4})(?!\d)")
# Indian passport: 1 letter + 7 digits (common format)
passport_re = re.compile(r"\b([A-Za-z])\d{7}\b")
# IPv4 quick pattern; validated via ipaddress
ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False

# Masking helpers
def mask_phone(s: str) -> str:
    def repl(m):
        num = m.group(1)
        return f"{num[:2]}{'X'*6}{num[-2:]}"
    return phone_10_re.sub(repl, s)

def mask_aadhar(s: str) -> str:
    def repl(_m):
        return "XXXX XXXX XXXX"
    return aadhar_re.sub(repl, s)

def mask_passport(s: str) -> str:
    def repl(m):
        start = m.group(1)
        return f"{start}{'X'*4}{m.group(0)[-2:]}"
    return passport_re.sub(repl, s)

def mask_upi(s: str) -> str:
    def repl(m):
        upi = m.group(0)
        local, domain = upi.split('@', 1)
        if phone_10_re.fullmatch(local):
            masked_local = f"{local[:2]}{'X'*6}{local[-2:]}"
        else:
            keep = 2 if len(local) >= 2 else 1
            masked_local = f"{local[:keep]}XXX"
        return f"{masked_local}@{domain}"
    return upi_re.sub(repl, s)

def mask_email(s: str) -> str:
    def repl(m):
        em = m.group(0)
        local, domain = em.split('@', 1)
        keep = 2 if len(local) >= 2 else 1
        return f"{local[:keep]}XXX@{domain}"
    return email_re.sub(repl, s)

# Combinatorial heuristics
def is_full_name(record: Dict[str, Any]) -> bool:
    name = record.get("name")
    fn = record.get("first_name")
    ln = record.get("last_name")

    def looks_full(n: str) -> bool:
        parts = [p for p in re.split(r"\s+", n.strip()) if p]
        return len(parts) >= 2 and all(p.isalpha() for p in parts[:2])

    if isinstance(name, str) and looks_full(name):
        return True
    if isinstance(fn, str) and isinstance(ln, str) and fn.strip() and ln.strip():
        return True
    return False

def has_email(record: Dict[str, Any]) -> bool:
    v = record.get("email")
    return isinstance(v, str) and email_re.search(v) is not None

def has_physical_address(record: Dict[str, Any]) -> bool:
    addr = record.get("address")
    city = record.get("city")
    state = record.get("state")
    pin_code = record.get("pin_code")

    pin_ok = False
    if isinstance(pin_code, (str, int)):
        s = str(pin_code)
        if re.fullmatch(r"\d{6}", s):
            pin_ok = True

    addr_ok = isinstance(addr, str) and len(addr.strip()) >= 6 and bool(re.search(r"\d", addr))
    city_ok = isinstance(city, str) and len(city.strip()) >= 2
    state_ok = isinstance(state, str) and len(state.strip()) >= 2
    # Require PIN plus at least one of addr/city/state
    return pin_ok and (addr_ok or city_ok or state_ok)

def has_device_or_ip(record: Dict[str, Any]) -> bool:
    dev = record.get("device_id")
    ip = record.get("ip_address")
    if isinstance(dev, str) and dev.strip():
        return True
    if isinstance(ip, str) and is_valid_ipv4(ip.strip()):
        return True
    return False

# Standalone PII (A) detection
def detect_A_fields(record: Dict[str, Any]):
    A = {"phone": False, "aadhar": False, "passport": False, "upi": False}

    # Phones in phone-like keys (allow values that are not strings)
    for k in PHONE_KEYS:
        v = record.get(k)
        if v is None:
            continue
        sv = str(v)
        if phone_10_re.search(sv):
            A["phone"] = True

    # Aadhaar in known keys
    for k in record.keys():
        if k.lower() in AADHAR_KEYS:
            v = record.get(k)
            if v is None:
                continue
            sv = str(v)
            if aadhar_re.search(sv):
                A["aadhar"] = True

    # Passport in passport key only (avoid FPs elsewhere)
    v = record.get("passport")
    if v is not None:
        sv = str(v)
        if passport_re.search(sv):
            A["passport"] = True

    # UPI
    for k in UPI_KEYS:
        v = record.get(k)
        if v is None:
            continue
        sv = str(v)
        if upi_re.search(sv):
            A["upi"] = True

    return A

def redact_record(record: Dict[str, Any]):
    rec = dict(record)  # shallow copy

    A = detect_A_fields(rec)
    B_name = is_full_name(rec)
    B_email = has_email(rec)
    B_phys = has_physical_address(rec)
    B_devip = has_device_or_ip(rec)

    B_count = sum([B_name, B_email, B_phys, B_devip])
    pii = any(A.values()) or (B_count >= 2)

    # Redact standalone A types everywhere relevant
    if A["phone"]:
        for k in PHONE_KEYS:
            v = rec.get(k)
            if v is not None:
                rec[k] = mask_phone(str(v))
    if A["aadhar"]:
        for k, v in list(rec.items()):
            if k.lower() in AADHAR_KEYS and v is not None:
                rec[k] = mask_aadhar(str(v))
    if A["passport"]:
        v = rec.get("passport")
        if v is not None:
            rec["passport"] = mask_passport(str(v))
    if A["upi"]:
        for k in UPI_KEYS:
            v = rec.get(k)
            if v is not None:
                rec[k] = mask_upi(str(v))

    # Redact combinatorial B only if combinatorial condition met
    if B_count >= 2:
        # Name
        if B_name:
            name = rec.get("name")
            if isinstance(name, str) and name.strip():
                parts = name.split()
                rec["name"] = " ".join(p + ("X" * max(0, len(p)-1)) for p in parts)
            fn = rec.get("first_name")
            if isinstance(fn, str) and fn.strip():
                rec["first_name"] = fn + ("X" * max(0, len(fn)-1))
            ln = rec.get("last_name")
            if isinstance(ln, str) and ln.strip():
                rec["last_name"] = ln + ("X" * max(0, len(ln)-1))

        # Email
        if B_email:
            v = rec.get("email")
            if isinstance(v, str):
                rec["email"] = mask_email(v)

        # Physical address
        if B_phys:
            if isinstance(rec.get("address"), str):
                rec["address"] = "[REDACTED_PII]"
            if isinstance(rec.get("city"), str):
                c = rec["city"]
                rec["city"] = (c + "XXX") if c else "XXX"
            if isinstance(rec.get("state"), str):
                s = rec["state"]
                rec["state"] = (s + "XXX") if s else "XXX"
            if rec.get("pin_code") is not None:
                rec["pin_code"] = "XXXXXX"

        # Device or IP
        if B_devip:
            if isinstance(rec.get("device_id"), str) and rec.get("device_id"):
                rec["device_id"] = "[REDACTED_PII]"
            if isinstance(rec.get("ip_address"), str) and rec.get("ip_address"):
                rec["ip_address"] = "XXX.XXX.XXX.XXX"

    return rec, pii

# -------- Robust CSV/JSON handling --------

DATA_COL_CANDIDATES = [
    "data_json", "data json", "data", "payload", "json", "data_obj", "data_blob",
    "data_json_-_sheet1"
]
RID_CANDIDATES = ["record_id", "recordid", "id"]

def looks_like_json_text(s: str) -> bool:
    if not isinstance(s, str):
        return False
    t = s.strip()
    return (t.startswith("{") and t.endswith("}")) or (t.startswith("[") and t.endswith("]"))

def parse_json_forgiving(s: Optional[str]) -> Optional[Dict[str, Any]]:
    if s is None:
        return None
    t = s.strip()
    if not t:
        return None
    # Try normal
    try:
        obj = json.loads(t)
        # Some sources double-encode JSON: first loads returns a string that itself is JSON
        if isinstance(obj, str) and looks_like_json_text(obj):
            obj2 = json.loads(obj)
            if isinstance(obj2, dict):
                return obj2
            return None
        if isinstance(obj, dict):
            return obj
        return None
    except Exception:
        pass
    # Try single->double quote heuristic
    try:
        obj = json.loads(t.replace("'", '"'))
        if isinstance(obj, str) and looks_like_json_text(obj):
            obj2 = json.loads(obj)
            if isinstance(obj2, dict):
                return obj2
            return None
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    # Try trimming wrapping quotes and collapsing doubled quotes
    try:
        tt = t
        if tt == tt[-1] and tt in ("'", '"'):
            tt = tt[1:-1]
        tt = tt.replace('""', '"').replace("\\\"", "\"")
        obj = json.loads(tt)
        if isinstance(obj, str) and looks_like_json_text(obj):
            obj2 = json.loads(obj)
            if isinstance(obj2, dict):
                return obj2
            return None
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    return None

def find_record_id_field(fieldnames):
    lowered = {h.strip().lower(): h for h in fieldnames}
    for k in RID_CANDIDATES:
        if k in lowered:
            return lowered[k]
    # fallback: exact 'record_id' if present
    return lowered.get("record_id", fieldnames)

def find_data_col_field(fieldnames):
    lowered = {h.strip().lower(): h for h in fieldnames}
    for cand in DATA_COL_CANDIDATES:
        if cand in lowered:
            return lowered[cand]
    return None

def build_record_from_row(row: Dict[str, str], rid_field: str, data_field: Optional[str]) -> Dict[str, Any]:
    # If a JSON blob column is present and parseable, use that
    if data_field:
        txt = row.get(data_field)
        obj = parse_json_forgiving(txt)
        if obj is not None:
            return obj
        # If it looks like JSON but parse failed, try gentle fixups before giving up
        if isinstance(txt, str) and "{" in txt and "}" in txt:
            tentative = txt.strip().strip('"').replace('""', '"')
            obj = parse_json_forgiving(tentative)
            if obj is not None:
                return obj

    # Otherwise, reconstruct from row columns (excluding record_id)
    rec: Dict[str, Any] = {}
    for k, v in row.items():
        if k == rid_field:
            continue
        if v is None:
            continue
        sv = str(v).strip()
        if not sv:
            continue
        # If a cell contains JSON, try to parse and merge
        if looks_like_json_text(sv):
            sub = parse_json_forgiving(sv)
            if isinstance(sub, dict):
                # Merge, do not overwrite existing keys
                for sk, sv2 in sub.items():
                    if sk not in rec:
                        rec[sk] = sv2
                continue
        # Keep as is for simple scalar fields
        rec[k.strip()] = sv
    return rec

def process_file(input_csv: str, output_csv: str):
    # Use utf-8-sig to handle BOM that can appear in CSV exports from spreadsheets
    with open(input_csv, newline='', encoding='utf-8-sig') as f_in, open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
        reader = csv.DictReader(f_in)
        if reader.fieldnames is None:
            raise RuntimeError("CSV has no header row; cannot proceed.")
        rid_field = find_record_id_field(reader.fieldnames)
        data_field = find_data_col_field(reader.fieldnames)

        writer = csv.DictWriter(f_out, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()

        for row in reader:
            # Record ID (string-safe)
            rid = row.get(rid_field)
            # Build best-effort data dict from either the JSON blob column or the columns themselves
            data = build_record_from_row(row, rid_field, data_field)
            redacted, is_pii = redact_record(data)
            writer.writerow({
                "record_id": rid,
                "redacted_data_json": json.dumps(redacted, ensure_ascii=False),
                "is_pii": str(bool(is_pii))
            })

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detector_full_candidate_name.py <input_csv>")
        sys.exit(1)
    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"
    process_file(input_csv, output_csv)
    print(f"Processed -> {output_csv}")

if __name__ == '__main__':
    main()
