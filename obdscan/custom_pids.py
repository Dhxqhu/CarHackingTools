"""Per-make / per-vehicle custom Mode 01 PID profiles (reverse-engineering store)."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path

PROFILES_FILE = Path.home() / ".config" / "obdscan" / "pid_profiles.json"
# Back-compat with the first flat custom_pids.json layout
LEGACY_CUSTOM_FILE = Path.home() / ".config" / "obdscan" / "custom_pids.json"

# Also exported under old name for callers
CUSTOM_PID_FILE = PROFILES_FILE

FORMULA_HELP = {
    "raw": "Hex dump of returned bytes",
    "u8": "Unsigned byte A",
    "temp": "Temperature °C  (A - 40)",
    "pct": "Percent 0–100  (A * 100 / 255)",
    "trim": "Fuel trim %  ((A - 128) * 100 / 128)",
    "u16": "Unsigned 16-bit  ((A << 8) + B)",
    "rpm": "Engine RPM  (((A << 8) + B) / 4)",
    "maf": "MAF g/s  (((A << 8) + B) / 100)",
    "timing": "Timing advance °  (A / 2 - 64)",
    "volt": "Voltage  (((A << 8) + B) / 1000)",
    "lambda": "Equivalence ratio λ  (((A << 8) + B) * 2 / 65536)",
    "scale": "Custom: (A or A:B) * mult + offset",
}

# Common WMI prefixes → make slug (best-effort; profiles can override)
WMI_TO_MAKE: dict[str, str] = {
    "1FA": "ford", "1FB": "ford", "1FC": "ford", "1FD": "ford", "1FT": "ford",
    "1FM": "ford", "1ZV": "ford", "2FA": "ford", "2FM": "ford", "2FT": "ford",
    "3FA": "ford", "3FM": "ford",
    "1G1": "chevy", "1G6": "cadillac", "1GC": "chevy", "1GT": "gmc",
    "2G1": "chevy", "3G1": "chevy", "1GN": "chevy",
    "1C3": "chrysler", "1C4": "chrysler", "1C6": "ram", "2C3": "chrysler",
    "1J4": "jeep", "1J8": "jeep",
    "1N4": "nissan", "1N6": "nissan", "3N1": "nissan", "JN1": "nissan",
    "4T1": "toyota", "4T3": "toyota", "5TD": "toyota", "JTD": "toyota",
    "2T1": "toyota", "5TF": "toyota", "5TE": "toyota",
    "1HG": "honda", "2HG": "honda", "19X": "honda", "JHM": "honda",
    "5FN": "honda", "SHH": "honda",
    "KM8": "hyundai", "KMH": "hyundai", "5NP": "hyundai",
    "KND": "kia", "5XY": "kia",
    "WBA": "bmw", "WBS": "bmw", "5UX": "bmw", "5YM": "bmw",
    "WDD": "mercedes", "WDC": "mercedes", "4JG": "mercedes",
    "WAU": "audi", "WA1": "audi", "TRU": "audi",
    "WVW": "vw", "3VW": "vw", "1VW": "vw",
    "JF1": "subaru", "JF2": "subaru", "4S3": "subaru", "4S4": "subaru",
    "JM1": "mazda", "JM3": "mazda", "3MZ": "mazda",
    "KL1": "chevy", "KL4": "buick",  # GM Korea / Buick
}


def _need(d: list[int], n: int) -> bool:
    return len(d) >= n


def make_formatter(formula: str, mult: float = 1.0, offset: float = 0.0, wide: bool = False):
    formula = formula.lower().strip()

    def raw(d: list[int]) -> str:
        return " ".join(f"{b:02X}" for b in d) if d else "—"

    def u8(d: list[int]) -> str:
        return f"{d[0]}" if d else "—"

    def temp(d: list[int]) -> str:
        return f"{d[0] - 40}" if d else "—"

    def pct(d: list[int]) -> str:
        return f"{d[0] * 100 / 255:.1f}" if d else "—"

    def trim(d: list[int]) -> str:
        return f"{(d[0] - 128) * 100 / 128:.1f}" if d else "—"

    def u16(d: list[int]) -> str:
        return f"{(d[0] << 8) + d[1]}" if _need(d, 2) else "—"

    def rpm(d: list[int]) -> str:
        return f"{((d[0] << 8) + d[1]) / 4:.0f}" if _need(d, 2) else "—"

    def maf(d: list[int]) -> str:
        return f"{((d[0] << 8) + d[1]) / 100:.2f}" if _need(d, 2) else "—"

    def timing(d: list[int]) -> str:
        return f"{d[0] / 2 - 64:.1f}" if d else "—"

    def volt(d: list[int]) -> str:
        return f"{((d[0] << 8) + d[1]) / 1000:.3f}" if _need(d, 2) else "—"

    def lam(d: list[int]) -> str:
        return f"{((d[0] << 8) + d[1]) * 2 / 65536:.3f}" if _need(d, 2) else "—"

    def scale(d: list[int]) -> str:
        if not d:
            return "—"
        if wide:
            if not _need(d, 2):
                return "—"
            raw_v = (d[0] << 8) + d[1]
        else:
            raw_v = d[0]
        return f"{raw_v * mult + offset:.3f}"

    return {
        "raw": raw,
        "u8": u8,
        "temp": temp,
        "pct": pct,
        "trim": trim,
        "u16": u16,
        "rpm": rpm,
        "maf": maf,
        "timing": timing,
        "volt": volt,
        "lambda": lam,
        "scale": scale,
    }.get(formula, raw)


def normalize_pid_spec(spec: dict) -> dict | None:
    if not isinstance(spec, dict):
        return None
    pid = str(spec.get("pid", "")).strip().upper()
    if not re.fullmatch(r"[0-9A-F]{2}", pid):
        return None
    out = {
        "pid": pid,
        "unit": str(spec.get("unit", "")),
        "formula": str(spec.get("formula", "raw")).lower(),
        "mult": float(spec.get("mult", 1.0)),
        "offset": float(spec.get("offset", 0.0)),
        "wide": bool(spec.get("wide", False)),
        "note": str(spec.get("note", "")),
    }
    # Preserve provenance stamped when saving from a live car
    for key in ("saved_with_vin", "saved_with_year"):
        if spec.get(key) not in (None, "", "—"):
            out[key] = spec[key]
    return out


def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", text.strip().lower())
    return s.strip("_") or "profile"


def make_guess_from_vin(vin: str | None) -> tuple[str | None, str | None]:
    """Return (make_slug, wmi) from VIN when possible."""
    if not vin or len(vin) < 3:
        return None, None
    wmi = vin[:3].upper()
    return WMI_TO_MAKE.get(wmi), wmi


# SAE J272 VIN position 10 — 30-year repeating cycle (I/O/Q unused)
_VIN_YEAR_CODES = "ABCDEFGHJKLMNPRSTVWXY123456789"


def model_year_from_vin(vin: str | None, *, now_year: int | None = None) -> int | None:
    """Decode model year from VIN digit 10; pick the 30-year cycle nearest to now."""
    if not vin or len(vin) < 10:
        return None
    code = vin[9].upper()
    idx = _VIN_YEAR_CODES.find(code)
    if idx < 0:
        return None
    ref = now_year if now_year is not None else datetime.now().year
    candidates = [1980 + idx, 2010 + idx, 2040 + idx]
    return min(candidates, key=lambda y: (abs(y - ref), -y))


def parse_year_range(text: str) -> tuple[int | None, int | None]:
    """
    Parse '2018', '2018-2022', '2018+', '2015-'.
    Returns (year_from, year_to); either side may be None (open).
    Empty → (None, None) = any year.
    """
    raw = (text or "").strip().replace(" ", "")
    if not raw or raw in {"*", "any", "all"}:
        return None, None
    if re.fullmatch(r"\d{4}\+", raw):
        return int(raw[:-1]), None
    if re.fullmatch(r"\d{4}-", raw):
        return None, int(raw[:-1])
    if re.fullmatch(r"\d{4}-\d{4}", raw):
        a, b = raw.split("-", 1)
        lo, hi = int(a), int(b)
        return (lo, hi) if lo <= hi else (hi, lo)
    if re.fullmatch(r"\d{4}", raw):
        y = int(raw)
        return y, y
    raise ValueError(f"Bad year range '{text}' — use 2018, 2018-2022, or 2018+")


def format_year_range(year_from: int | None, year_to: int | None) -> str:
    if year_from is None and year_to is None:
        return "any"
    if year_from is not None and year_to is not None:
        if year_from == year_to:
            return str(year_from)
        return f"{year_from}-{year_to}"
    if year_from is not None:
        return f"{year_from}+"
    return f"-{year_to}"


def profile_years(prof: dict) -> tuple[int | None, int | None]:
    yf, yt = prof.get("year_from"), prof.get("year_to")
    return (
        int(yf) if yf is not None and str(yf).strip() != "" else None,
        int(yt) if yt is not None and str(yt).strip() != "" else None,
    )


def year_in_profile(year: int | None, prof: dict) -> bool:
    """True if year fits profile bounds. Unknown vehicle year only matches unbound profiles."""
    yf, yt = profile_years(prof)
    if yf is None and yt is None:
        return True
    if year is None:
        return False
    if yf is not None and year < yf:
        return False
    if yt is not None and year > yt:
        return False
    return True


def empty_profile(
    profile_id: str,
    label: str = "",
    makes: list[str] | None = None,
    year_from: int | None = None,
    year_to: int | None = None,
) -> dict:
    return {
        "id": profile_id,
        "label": label or profile_id,
        "makes": [m.lower() for m in (makes or [profile_id])],
        "year_from": year_from,
        "year_to": year_to,
        "vin_wmi": [],
        "notes": "",
        "vehicle_hints": {},
        "source_vehicle": None,
        "working_vehicles": [],
        "pids": {},
        "scans": [],
        "import_log": [],
    }


def customs_to_catalog(customs: dict[str, dict]) -> dict[str, tuple[str, str, object]]:
    cat: dict[str, tuple[str, str, object]] = {}
    for name, spec in customs.items():
        clean = normalize_pid_spec(spec)
        if not clean:
            continue
        fmt = make_formatter(
            clean["formula"],
            mult=clean["mult"],
            offset=clean["offset"],
            wide=clean["wide"],
        )
        cat[name] = (clean["pid"], clean["unit"], fmt)
    return cat


def decode_support_bitfield(base: int, data: list[int]) -> tuple[list[int], bool]:
    pids: list[int] = []
    if len(data) < 4:
        return pids, False
    for i, byte in enumerate(data[:4]):
        for bit in range(8):
            if byte & (0x80 >> bit):
                pids.append(base + i * 8 + bit + 1)
    next_block = bool(data[3] & 0x01)
    return pids, next_block


def catalog_hex_set(catalog: dict[str, tuple]) -> set[str]:
    return {str(entry[0]).upper() for entry in catalog.values()}


class ProfileStore:
    """Make/vehicle-scoped custom PID tables + scan history."""

    def __init__(self, path: Path | None = None):
        self.path = path or PROFILES_FILE
        self.data: dict = {
            "version": 2,
            "active_profile": "",
            "profiles": {},
        }
        self.load()

    # --- persistence --------------------------------------------------------

    def load(self) -> None:
        if self.path.is_file():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = {}
            if isinstance(raw, dict) and raw.get("version") == 2 and "profiles" in raw:
                self.data = raw
                self._normalize_all()
                return
            # Unexpected shape — start fresh but try migrate below

        # Migrate flat v1 custom_pids.json if present
        if LEGACY_CUSTOM_FILE.is_file():
            try:
                legacy = json.loads(LEGACY_CUSTOM_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                legacy = {}
            if isinstance(legacy, dict) and legacy and "profiles" not in legacy:
                pids = {}
                for name, spec in legacy.items():
                    key = str(name).strip().upper()
                    clean = normalize_pid_spec(spec if isinstance(spec, dict) else {})
                    if key and clean:
                        pids[key] = clean
                if pids:
                    prof = empty_profile("legacy", "Migrated (unscoped)", makes=["legacy"])
                    prof["notes"] = "Imported from older flat custom_pids.json — reassign to a make."
                    prof["pids"] = pids
                    self.data["profiles"]["legacy"] = prof
                    self.data["active_profile"] = "legacy"
                    self.save()
                    return

        self._ensure_active()

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return self.path

    def _normalize_all(self) -> None:
        profiles = self.data.setdefault("profiles", {})
        for pid, prof in list(profiles.items()):
            if not isinstance(prof, dict):
                del profiles[pid]
                continue
            prof.setdefault("id", pid)
            prof.setdefault("label", pid)
            prof.setdefault("makes", [pid])
            prof.setdefault("year_from", None)
            prof.setdefault("year_to", None)
            prof.setdefault("vin_wmi", [])
            prof.setdefault("notes", "")
            prof.setdefault("vehicle_hints", {})
            prof.setdefault("source_vehicle", None)
            prof.setdefault("working_vehicles", [])
            prof.setdefault("pids", {})
            prof.setdefault("scans", [])
            prof.setdefault("import_log", [])
            clean_pids = {}
            for name, spec in prof["pids"].items():
                key = str(name).strip().upper()
                nspec = normalize_pid_spec(spec)
                if key and nspec:
                    clean_pids[key] = nspec
            prof["pids"] = clean_pids
            prof["makes"] = [str(m).lower() for m in prof["makes"]]
            prof["vin_wmi"] = [str(w).upper()[:3] for w in prof["vin_wmi"] if w]
            yf, yt = profile_years(prof)
            prof["year_from"], prof["year_to"] = yf, yt
        self._ensure_active()

    def _ensure_active(self) -> None:
        profiles = self.data.setdefault("profiles", {})
        active = self.data.get("active_profile") or ""
        if active not in profiles:
            self.data["active_profile"] = next(iter(profiles), "")

    # --- profile ops --------------------------------------------------------

    @property
    def active_id(self) -> str:
        return str(self.data.get("active_profile") or "")

    @property
    def profiles(self) -> dict[str, dict]:
        return self.data.setdefault("profiles", {})

    @property
    def active(self) -> dict | None:
        aid = self.active_id
        return self.profiles.get(aid) if aid else None

    @property
    def pids(self) -> dict[str, dict]:
        prof = self.active
        return prof["pids"] if prof else {}

    def list_summaries(self) -> list[tuple[str, str, int, str, str]]:
        """(id, label, pid_count, makes_csv, years)"""
        rows = []
        for pid, prof in sorted(self.profiles.items()):
            yf, yt = profile_years(prof)
            rows.append(
                (
                    pid,
                    prof.get("label", pid),
                    len(prof.get("pids", {})),
                    ", ".join(prof.get("makes", [])),
                    format_year_range(yf, yt),
                )
            )
        return rows

    def select(self, profile_id: str) -> bool:
        profile_id = slugify(profile_id)
        if profile_id not in self.profiles:
            return False
        self.data["active_profile"] = profile_id
        self.save()
        return True

    def create(
        self,
        profile_id: str,
        label: str = "",
        makes: list[str] | None = None,
        vin_wmi: list[str] | None = None,
        year_from: int | None = None,
        year_to: int | None = None,
        notes: str = "",
        activate: bool = True,
    ) -> dict:
        profile_id = slugify(profile_id)
        if profile_id in self.profiles:
            raise ValueError(f"Profile '{profile_id}' already exists")
        prof = empty_profile(
            profile_id,
            label=label or profile_id,
            makes=makes,
            year_from=year_from,
            year_to=year_to,
        )
        if vin_wmi:
            prof["vin_wmi"] = [w.upper()[:3] for w in vin_wmi if w]
        prof["notes"] = notes
        self.profiles[profile_id] = prof
        if activate or not self.active_id:
            self.data["active_profile"] = profile_id
        self.save()
        return prof

    def delete(self, profile_id: str) -> bool:
        profile_id = slugify(profile_id)
        if profile_id not in self.profiles:
            return False
        del self.profiles[profile_id]
        if self.data.get("active_profile") == profile_id:
            self.data["active_profile"] = next(iter(self.profiles), "")
        self.save()
        return True

    def clone(self, src_id: str, dest_id: str, label: str = "") -> dict:
        src_id, dest_id = slugify(src_id), slugify(dest_id)
        if src_id not in self.profiles:
            raise ValueError(f"Source profile '{src_id}' not found")
        if dest_id in self.profiles:
            raise ValueError(f"Destination '{dest_id}' already exists")
        prof = deepcopy(self.profiles[src_id])
        prof["id"] = dest_id
        prof["label"] = label or dest_id
        prof["scans"] = []
        self.profiles[dest_id] = prof
        self.save()
        return prof

    def makes_overlap(self, a_id: str, b_id: str) -> bool:
        a = self.profiles.get(slugify(a_id)) or {}
        b = self.profiles.get(slugify(b_id)) or {}
        sa = {m.lower() for m in a.get("makes", [])}
        sb = {m.lower() for m in b.get("makes", [])}
        return bool(sa & sb)

    def import_pids(
        self,
        src_id: str,
        dest_id: str | None = None,
        *,
        replace: bool = False,
    ) -> dict:
        """
        Copy PID table from src into dest (default: active).
        Returns {copied, skipped, replaced, cross_make}.
        """
        src_id = slugify(src_id)
        dest_id = slugify(dest_id) if dest_id else self.active_id
        if src_id not in self.profiles:
            raise ValueError(f"Source profile '{src_id}' not found")
        if not dest_id or dest_id not in self.profiles:
            raise RuntimeError("No destination profile — create/select one first")
        if src_id == dest_id:
            raise ValueError("Source and destination are the same profile")
        src = self.profiles[src_id]
        dest = self.profiles[dest_id]
        cross_make = not self.makes_overlap(src_id, dest_id)
        src_pids = src.get("pids") or {}
        if not src_pids:
            raise ValueError(f"Source '{src_id}' has no PIDs to import")
        dest_pids = dest.setdefault("pids", {})
        copied = skipped = replaced = 0
        if replace:
            dest["pids"] = {}
            dest_pids = dest["pids"]
        for name, spec in src_pids.items():
            clean = normalize_pid_spec(spec)
            if not clean:
                skipped += 1
                continue
            key = str(name).strip().upper()
            if key in dest_pids and not replace:
                # merge mode: keep existing, count skip
                skipped += 1
                continue
            if key in dest_pids:
                replaced += 1
            else:
                copied += 1
            # Stamp note so RE provenance is visible
            note = clean.get("note") or ""
            tag = f"[from:{src_id}]"
            if tag not in note:
                clean["note"] = f"{note} {tag}".strip() if note else tag
            dest_pids[key] = clean
        log = dest.setdefault("import_log", [])
        log.append(
            {
                "from": src_id,
                "at": datetime.now().isoformat(timespec="seconds"),
                "mode": "replace" if replace else "merge",
                "copied": copied,
                "skipped": skipped,
                "replaced": replaced,
                "cross_make": cross_make,
            }
        )
        dest["import_log"] = log[-20:]
        hint = dest.setdefault("vehicle_hints", {})
        hint["last_import_from"] = src_id
        hint["last_import_at"] = datetime.now().isoformat(timespec="seconds")
        if cross_make:
            hint["cross_make_import"] = True
        self.save()
        return {
            "copied": copied,
            "skipped": skipped,
            "replaced": replaced,
            "cross_make": cross_make,
            "src": src_id,
            "dest": dest_id,
            "total_src": len(src_pids),
        }

    def set_pid(self, name: str, spec: dict, *, vehicle: dict | None = None) -> None:
        if not self.active:
            raise RuntimeError("No active profile — create or select one first")
        key = str(name).strip().upper()
        clean = normalize_pid_spec(spec)
        if not key or not clean:
            raise ValueError("Invalid PID name/spec")
        if vehicle:
            vin = str(vehicle.get("VIN") or vehicle.get("vin") or "").strip()
            if vin and vin != "—":
                clean["saved_with_vin"] = vin.upper()[:17]
            year = vehicle.get("year") or vehicle.get("Year")
            if year is not None and str(year).strip() not in {"", "—"}:
                clean["saved_with_year"] = int(year) if str(year).isdigit() else year
        self.active["pids"][key] = clean
        if vehicle:
            self.record_working_vehicle(vehicle, reason=f"pid:{key}")
        else:
            self.save()

    def remove_pid(self, name: str) -> bool:
        if not self.active:
            return False
        key = str(name).strip().upper()
        if key not in self.active["pids"]:
            return False
        del self.active["pids"][key]
        self.save()
        return True

    def record_working_vehicle(
        self,
        info: dict | None,
        *,
        reason: str = "",
        set_as_source: bool = True,
    ) -> None:
        """Persist VIN + relevant car info on the active profile when a table is saved."""
        if not self.active or not info:
            return
        # Normalize to plain strings; drop empties
        snap: dict[str, str] = {}
        for k, v in info.items():
            if v is None:
                continue
            s = str(v).strip()
            if not s or s == "—":
                continue
            snap[str(k)] = s
        if not snap:
            return
        vin = snap.get("VIN") or snap.get("vin") or ""
        if vin:
            snap["VIN"] = vin.upper()[:17]
            year = model_year_from_vin(snap["VIN"])
            if year is not None:
                snap.setdefault("Year", str(year))
            make, wmi = make_guess_from_vin(snap["VIN"])
            if make:
                snap.setdefault("Make", make)
            if wmi:
                snap.setdefault("WMI", wmi)
                if wmi not in self.active.get("vin_wmi", []):
                    self.active.setdefault("vin_wmi", []).append(wmi)
        snap["recorded"] = datetime.now().isoformat(timespec="seconds")
        if reason:
            snap["reason"] = reason

        hints = self.active.setdefault("vehicle_hints", {})
        hints["updated"] = snap["recorded"]
        if snap.get("VIN"):
            hints["last_vin"] = snap["VIN"]
        if snap.get("Year"):
            try:
                hints["last_year"] = int(snap["Year"])
            except ValueError:
                hints["last_year"] = snap["Year"]
        if snap.get("Protocol"):
            hints["last_protocol"] = snap["Protocol"]
        if snap.get("Adapter"):
            hints["last_adapter"] = snap["Adapter"]
        if snap.get("Port"):
            hints["last_port"] = snap["Port"]

        if set_as_source:
            self.active["source_vehicle"] = dict(snap)

        history = self.active.setdefault("working_vehicles", [])
        last = history[-1] if history else None
        if (
            last
            and last.get("VIN")
            and last.get("VIN") == snap.get("VIN")
            and not str(reason).startswith("scan")
        ):
            history[-1] = {**last, **snap}
        else:
            history.append(snap)
        self.active["working_vehicles"] = history[-30:]
        self.save()

    def touch_vehicle_hints(
        self,
        vin: str | None = None,
        protocol: str | None = None,
        vehicle: dict | None = None,
    ) -> None:
        if vehicle:
            self.record_working_vehicle(vehicle, reason="touch")
            return
        if not self.active:
            return
        hints = self.active.setdefault("vehicle_hints", {})
        hints["updated"] = datetime.now().isoformat(timespec="seconds")
        if vin:
            hints["last_vin"] = vin
            wmi = vin[:3].upper() if len(vin) >= 3 else ""
            if wmi and wmi not in self.active.get("vin_wmi", []):
                self.active.setdefault("vin_wmi", []).append(wmi)
            year = model_year_from_vin(vin)
            if year is not None:
                hints["last_year"] = year
            self.record_working_vehicle(
                {"VIN": vin, "Protocol": protocol or ""},
                reason="vin-touch",
                set_as_source=not self.active.get("source_vehicle"),
            )
            return
        if protocol:
            hints["last_protocol"] = protocol
        self.save()

    def add_scan(
        self,
        hits: list[dict],
        vin: str | None = None,
        protocol: str | None = None,
        deep: bool = False,
        vehicle: dict | None = None,
    ) -> None:
        if not self.active:
            raise RuntimeError("No active profile")
        if vehicle is None and vin:
            vehicle = {"VIN": vin}
            if protocol:
                vehicle["Protocol"] = protocol
        year = None
        if vehicle and vehicle.get("Year"):
            try:
                year = int(vehicle["Year"])
            except (TypeError, ValueError):
                year = None
        if year is None:
            year = model_year_from_vin(
                (vehicle or {}).get("VIN") or vin
            )
        entry = {
            "saved": datetime.now().isoformat(timespec="seconds"),
            "vin": (vehicle or {}).get("VIN") or vin or "",
            "year": year,
            "protocol": (vehicle or {}).get("Protocol") or protocol or "",
            "deep": deep,
            "vehicle": {
                k: v
                for k, v in (vehicle or {}).items()
                if v not in (None, "", "—")
            },
            "hits": hits,
        }
        scans = self.active.setdefault("scans", [])
        scans.append(entry)
        self.active["scans"] = scans[-20:]
        if vehicle:
            self.record_working_vehicle(vehicle, reason="scan")
        else:
            self.touch_vehicle_hints(vin=vin, protocol=protocol)

    def profiles_for_exact_vin(self, vin: str | None) -> list[tuple[str, str, int]]:
        """
        Profiles that previously saw this exact VIN.
        Returns [(profile_id, how, pid_count)] ranked: source > history > scan.
        """
        if not vin or len(vin) < 11:
            return []
        vin_u = vin.strip().upper()
        ranked: list[tuple[int, str, str, int]] = []
        for pid, prof in self.profiles.items():
            how = None
            rank = 99
            src = str((prof.get("source_vehicle") or {}).get("VIN") or "").upper()
            if src == vin_u:
                how, rank = "source car", 0
            if how is None:
                for snap in prof.get("working_vehicles") or []:
                    if str(snap.get("VIN") or "").upper() == vin_u:
                        how, rank = "working history", 1
                        break
            if how is None:
                for scan in prof.get("scans") or []:
                    scan_vin = str(scan.get("vin") or "").upper()
                    veh_vin = str((scan.get("vehicle") or {}).get("VIN") or "").upper()
                    if vin_u in {scan_vin, veh_vin}:
                        how, rank = "saved scan", 2
                        break
            if how is not None:
                ranked.append((rank, pid, how, len(prof.get("pids") or {})))
        ranked.sort()
        # Deduplicate profile ids keeping best rank
        seen: set[str] = set()
        out: list[tuple[str, str, int]] = []
        for _, pid, how, n in ranked:
            if pid in seen:
                continue
            seen.add(pid)
            out.append((pid, how, n))
        return out

    def profiles_matching_vin(self, vin: str | None) -> list[str]:
        """Profiles whose make/WMI and year range fit this VIN (year-bounded first)."""
        if not vin or len(vin) < 3:
            return []
        wmi = vin[:3].upper()
        make, _ = make_guess_from_vin(vin)
        year = model_year_from_vin(vin)
        scored: list[tuple[int, str]] = []
        for pid, prof in self.profiles.items():
            wmi_hit = wmi in [w.upper() for w in prof.get("vin_wmi", [])]
            make_hit = bool(make and make in [m.lower() for m in prof.get("makes", [])])
            if not (wmi_hit or make_hit):
                continue
            if not year_in_profile(year, prof):
                continue
            yf, yt = profile_years(prof)
            # Prefer year-scoped profiles over "any year" make matches
            score = 0 if (yf is not None or yt is not None) else 1
            scored.append((score, pid))
        scored.sort()
        return [pid for _, pid in scored]

    def profiles_same_make_year_mismatch(self, vin: str | None) -> list[str]:
        """Same make/WMI but year outside profile range (crossover risk)."""
        if not vin or len(vin) < 3:
            return []
        wmi = vin[:3].upper()
        make, _ = make_guess_from_vin(vin)
        year = model_year_from_vin(vin)
        if year is None:
            return []
        out = []
        for pid, prof in self.profiles.items():
            wmi_hit = wmi in [w.upper() for w in prof.get("vin_wmi", [])]
            make_hit = bool(make and make in [m.lower() for m in prof.get("makes", [])])
            if not (wmi_hit or make_hit):
                continue
            yf, yt = profile_years(prof)
            if yf is None and yt is None:
                continue
            if not year_in_profile(year, prof):
                out.append(pid)
        return out

    def profile_matches_vin(self, profile_id: str, vin: str | None) -> bool | None:
        """True/False if we can judge; None if no VIN / no constraints."""
        if not vin or len(vin) < 3:
            return None
        prof = self.profiles.get(slugify(profile_id))
        if not prof:
            return None
        wmis = [w.upper() for w in prof.get("vin_wmi", [])]
        makes = [m.lower() for m in prof.get("makes", [])]
        yf, yt = profile_years(prof)
        if not wmis and not makes and yf is None and yt is None:
            return None
        wmi = vin[:3].upper()
        make, _ = make_guess_from_vin(vin)
        year = model_year_from_vin(vin)
        identity_ok = False
        if wmis and wmi in wmis:
            identity_ok = True
        elif make and make in makes:
            identity_ok = True
        elif not wmis and not makes:
            identity_ok = True  # year-only profile
        else:
            return False
        if not year_in_profile(year, prof):
            return False
        return True if identity_ok else None


# Back-compat helpers used by older call sites
def load_custom_pids(path: Path | None = None) -> dict[str, dict]:
    store = ProfileStore(path)
    return dict(store.pids)


def save_custom_pids(customs: dict[str, dict], path: Path | None = None) -> Path:
    store = ProfileStore(path)
    if not store.active:
        store.create("default", label="Default", makes=["default"], activate=True)
    store.active["pids"] = {}
    for name, spec in customs.items():
        clean = normalize_pid_spec(spec)
        if clean:
            store.active["pids"][str(name).upper()] = clean
    return store.save()
