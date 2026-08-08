#!/usr/bin/env python3
"""
obdscan — full-featured CLI OBD-II application for ELM327 dongles.

Interactive module menu (default) or scriptable subcommands.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console, Group
    from rich.columns import Columns
    from rich.live import Live
    from rich.panel import Panel
    from rich.prompt import Confirm, Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Missing dependency: rich  (pip install rich)", file=sys.stderr)
    sys.exit(1)

from dtc_db import DEFAULT_DTC_DB, load_dtc_db, lookup_code
from elm import ElmSession, parse_dtc_response, parse_mode01
from custom_pids import (
    CUSTOM_PID_FILE,
    FORMULA_HELP,
    ProfileStore,
    catalog_hex_set,
    customs_to_catalog,
    decode_support_bitfield,
    format_year_range,
    make_guess_from_vin,
    model_year_from_vin,
    parse_year_range,
    profile_years,
    slugify,
)

try:
    from enhanced import interactive_enhanced_menu, show_manufacturer_list, show_pack_detail
    from manufacturers import get_pack, list_packs
    from doip_session import HAS_DOIP, discover_vehicles, probe_pack_modules, DoipSession, read_interesting_dids
except ImportError as _enh_exc:  # pragma: no cover
    interactive_enhanced_menu = None  # type: ignore
    HAS_DOIP = False
    _IMPORT_ERR = _enh_exc
else:
    _IMPORT_ERR = None

CONSOLE = Console()
HERE = Path(__file__).resolve().parent
DEFAULT_PORT = os.environ.get("OBD_PORT", "/dev/rfcomm0")
SAVED_CODES_DIR = Path.home() / "Documents" / "Saved Codes"

# --- Mode 01 decode helpers (SAE J1979) --------------------------------------

def _need(d: list[int], n: int) -> bool:
    return len(d) >= n


def _u8(d: list[int]) -> str:
    return f"{d[0]}" if d else "—"


def _temp_c(d: list[int]) -> str:
    return f"{d[0] - 40}" if d else "—"


def _pct255(d: list[int]) -> str:
    return f"{d[0] * 100 / 255:.1f}" if d else "—"


def _trim(d: list[int]) -> str:
    return f"{(d[0] - 128) * 100 / 128:.1f}" if d else "—"


def _o2_v(d: list[int]) -> str:
    return f"{d[0] / 200:.3f}" if d else "—"


def _o2_stft(d: list[int]) -> str:
    if len(d) < 2 or d[1] == 0xFF:
        return "—"
    return f"{(d[1] - 128) * 100 / 128:.1f}"


def _u16(d: list[int]) -> str:
    return f"{(d[0] << 8) + d[1]}" if _need(d, 2) else "—"


def _rpm(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) / 4:.0f}" if _need(d, 2) else "—"


def _maf(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) / 100:.2f}" if _need(d, 2) else "—"


def _timing(d: list[int]) -> str:
    return f"{d[0] / 2 - 64:.1f}" if d else "—"


def _fuel_press(d: list[int]) -> str:
    return f"{d[0] * 3}" if d else "—"


def _fuel_rail_rel(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) * 0.079:.1f}" if _need(d, 2) else "—"


def _fuel_rail_gauge(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) * 10}" if _need(d, 2) else "—"


def _evap_pa(d: list[int]) -> str:
    if not _need(d, 2):
        return "—"
    raw = (d[0] << 8) + d[1]
    if raw & 0x8000:
        raw -= 0x10000
    return f"{raw / 4:.2f}"


def _evap_abs(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) / 200:.2f}" if _need(d, 2) else "—"


def _ctrl_v(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) / 1000:.3f}" if _need(d, 2) else "—"


def _abs_load(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) * 100 / 255:.1f}" if _need(d, 2) else "—"


def _eq_ratio(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) * 2 / 65536:.3f}" if _need(d, 2) else "—"


def _wb_lambda(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) * 2 / 65536:.3f}" if _need(d, 2) else "—"


def _wb_volts(d: list[int]) -> str:
    return f"{((d[2] << 8) + d[3]) * 8 / 65536:.3f}" if _need(d, 4) else "—"


def _cat_temp(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) / 10 - 40:.1f}" if _need(d, 2) else "—"


def _fuel_rate(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) / 20:.2f}" if _need(d, 2) else "—"


def _inj_timing(d: list[int]) -> str:
    return f"{(((d[0] << 8) + d[1]) - 26880) / 128:.2f}" if _need(d, 2) else "—"


def _fuel_rail_abs(d: list[int]) -> str:
    return f"{((d[0] << 8) + d[1]) * 10}" if _need(d, 2) else "—"


def _torque_pct(d: list[int]) -> str:
    return f"{d[0] - 125}" if d else "—"


def _fuel_status(d: list[int]) -> str:
    if not d:
        return "—"
    labels = {
        1: "OL",
        2: "CL",
        4: "OL-drive",
        8: "OL-fault",
        16: "CL-fault",
    }
    a = labels.get(d[0], f"0x{d[0]:02X}")
    if len(d) > 1 and d[1]:
        b = labels.get(d[1], f"0x{d[1]:02X}")
        return f"{a}/{b}"
    return a


def _obd_std(d: list[int]) -> str:
    names = {
        1: "OBD-II CARB",
        2: "OBD EPA",
        3: "OBD + OBD-II",
        4: "OBD-I",
        5: "not OBD",
        6: "EOBD",
        7: "EOBD + OBD-II",
        8: "EOBD + OBD",
        9: "EOBD + OBD + OBD-II",
        10: "JOBD",
        11: "JOBD + OBD-II",
        12: "JOBD + EOBD",
        13: "JOBD + EOBD + OBD-II",
        17: "EMD",
        18: "EMD+",
        19: "HD OBD-C",
        20: "HD OBD",
        21: "WWH OBD",
        23: "HD EOBD-I",
        24: "HD EOBD-I N",
        25: "HD EOBD-II",
        26: "HD EOBD-II N",
        28: "OBDBr-1",
        29: "OBDBr-2",
    }
    return names.get(d[0], f"0x{d[0]:02X}") if d else "—"


def _fuel_type(d: list[int]) -> str:
    names = {
        0: "NA",
        1: "Gasoline",
        2: "Methanol",
        3: "Ethanol",
        4: "Diesel",
        5: "LPG",
        6: "CNG",
        7: "Propane",
        8: "Electric",
        9: "Bifuel gas",
        10: "Bifuel methanol",
        11: "Bifuel ethanol",
        12: "Bifuel LPG",
        13: "Bifuel CNG",
        14: "Bifuel propane",
        15: "Bifuel electric",
        16: "Bifuel electric/comb",
        17: "Hybrid gasoline",
        18: "Hybrid ethanol",
        19: "Hybrid diesel",
        20: "Hybrid electric",
        21: "Hybrid mixed",
        22: "Hybrid regenerative",
    }
    return names.get(d[0], f"0x{d[0]:02X}") if d else "—"


# PID catalog: name -> (mode01 hex, unit label, formatter(data_bytes)->str)
# Unsupported PIDs simply return "—" / NO DATA on a given car — that is normal.
PID_CATALOG: dict[str, tuple[str, str, object]] = {
    # Core engine
    "FUEL_STATUS": ("03", "", _fuel_status),
    "LOAD": ("04", "%", _pct255),
    "COOLANT": ("05", "°C", _temp_c),
    "STFT_B1": ("06", "%", _trim),
    "LTFT_B1": ("07", "%", _trim),
    "STFT_B2": ("08", "%", _trim),
    "LTFT_B2": ("09", "%", _trim),
    "FUEL_PRESS": ("0A", "kPa", _fuel_press),
    "MAP": ("0B", "kPa", _u8),
    "RPM": ("0C", "rpm", _rpm),
    "SPEED": ("0D", "km/h", _u8),
    "TIMING": ("0E", "°", _timing),
    "IAT": ("0F", "°C", _temp_c),
    "MAF": ("10", "g/s", _maf),
    "THROTTLE": ("11", "%", _pct255),
    # Narrowband O2 voltage (A) + per-sensor STFT (B) when present
    "O2_B1S1": ("14", "V", _o2_v),
    "O2_B1S1_STFT": ("14", "%", _o2_stft),
    "O2_B1S2": ("15", "V", _o2_v),
    "O2_B1S2_STFT": ("15", "%", _o2_stft),
    "O2_B1S3": ("16", "V", _o2_v),
    "O2_B1S4": ("17", "V", _o2_v),
    "O2_B2S1": ("18", "V", _o2_v),
    "O2_B2S1_STFT": ("18", "%", _o2_stft),
    "O2_B2S2": ("19", "V", _o2_v),
    "O2_B2S2_STFT": ("19", "%", _o2_stft),
    "O2_B2S3": ("1A", "V", _o2_v),
    "O2_B2S4": ("1B", "V", _o2_v),
    "OBD_STD": ("1C", "", _obd_std),
    "RUNTIME": ("1F", "s", _u16),
    "MIL_DIST": ("21", "km", _u16),
    "FUEL_RAIL_REL": ("22", "kPa", _fuel_rail_rel),
    "FUEL_RAIL": ("23", "kPa", _fuel_rail_gauge),
    # Wideband / AFR sensors (lambda + voltage)
    "WB_B1S1_EQ": ("24", "λ", _wb_lambda),
    "WB_B1S1_V": ("24", "V", _wb_volts),
    "WB_B1S2_EQ": ("25", "λ", _wb_lambda),
    "WB_B1S2_V": ("25", "V", _wb_volts),
    "WB_B1S3_EQ": ("26", "λ", _wb_lambda),
    "WB_B1S4_EQ": ("27", "λ", _wb_lambda),
    "WB_B2S1_EQ": ("28", "λ", _wb_lambda),
    "WB_B2S1_V": ("28", "V", _wb_volts),
    "WB_B2S2_EQ": ("29", "λ", _wb_lambda),
    "WB_B2S2_V": ("29", "V", _wb_volts),
    "WB_B2S3_EQ": ("2A", "λ", _wb_lambda),
    "WB_B2S4_EQ": ("2B", "λ", _wb_lambda),
    "EGR_CMD": ("2C", "%", _pct255),
    "EGR_ERR": ("2D", "%", _trim),
    "EVAP_PCT": ("2E", "%", _pct255),
    "FUEL_LEVEL": ("2F", "%", _pct255),
    "WARMUPS": ("30", "", _u8),
    "CLR_DIST": ("31", "km", _u16),
    "EVAP_PA": ("32", "Pa", _evap_pa),
    "BARO": ("33", "kPa", _u8),
    "CAT_B1S1": ("3C", "°C", _cat_temp),
    "CAT_B2S1": ("3D", "°C", _cat_temp),
    "CAT_B1S2": ("3E", "°C", _cat_temp),
    "CAT_B2S2": ("3F", "°C", _cat_temp),
    "CTRL_MOD_V": ("42", "V", _ctrl_v),
    "ABS_LOAD": ("43", "%", _abs_load),
    "EQ_RATIO": ("44", "λ", _eq_ratio),
    "REL_THROTTLE": ("45", "%", _pct255),
    "AMBIENT": ("46", "°C", _temp_c),
    "ABS_THROTTLE_B": ("47", "%", _pct255),
    "ABS_THROTTLE_C": ("48", "%", _pct255),
    "ACCEL_D": ("49", "%", _pct255),
    "ACCEL_E": ("4A", "%", _pct255),
    "ACCEL_F": ("4B", "%", _pct255),
    "THROTTLE_ACT": ("4C", "%", _pct255),
    "MIL_TIME": ("4D", "min", _u16),
    "CLR_TIME": ("4E", "min", _u16),
    "FUEL_TYPE": ("51", "", _fuel_type),
    "ETHANOL": ("52", "%", _pct255),
    "EVAP_ABS": ("53", "kPa", _evap_abs),
    "STFT2_B1": ("55", "%", _trim),
    "LTFT2_B1": ("56", "%", _trim),
    "STFT2_B2": ("57", "%", _trim),
    "LTFT2_B2": ("58", "%", _trim),
    "FUEL_RAIL_ABS": ("59", "kPa", _fuel_rail_abs),
    "REL_ACCEL": ("5A", "%", _pct255),
    "HYBRID_BAT": ("5B", "%", _pct255),
    "OIL_TEMP": ("5C", "°C", _temp_c),
    "INJ_TIMING": ("5D", "°", _inj_timing),
    "FUEL_RATE": ("5E", "L/h", _fuel_rate),
    "TQ_DEMAND": ("61", "%", _torque_pct),
    "TQ_ACTUAL": ("62", "%", _torque_pct),
    "TQ_REF": ("63", "Nm", _u16),
}

DEFAULT_LIVE = ["RPM", "SPEED", "COOLANT", "LOAD", "THROTTLE"]
# ELM queries PIDs one-by-one; large sets make each refresh noticeably slower.
LIVE_PID_WARN_COUNT = 6
LIVE_PID_CONFIRM_COUNT = 12
GRAPH_HISTORY = 72
GRAPH_HEIGHT = 8

# Common raw commands shown by `help` in the raw AT/OBD prompt
RAW_AT_COMMANDS: list[tuple[str, str]] = [
    ("ATZ", "Reset adapter"),
    ("ATI", "Adapter identification"),
    ("ATRV", "Adapter-measured battery voltage"),
    ("ATDP", "Describe current protocol"),
    ("ATDPN", "Protocol number"),
    ("ATSP0", "Auto protocol select"),
    ("ATE0", "Echo off"),
    ("ATE1", "Echo on"),
    ("ATH0", "Headers off"),
    ("ATH1", "Headers on"),
    ("ATL0", "Linefeeds off"),
    ("ATWS", "Warm start"),
]

RAW_OBD_COMMANDS: list[tuple[str, str]] = [
    ("03", "Read stored DTCs"),
    ("04", "Clear DTCs / MIL"),
    ("07", "Read pending DTCs"),
    ("0A", "Read permanent DTCs"),
    ("0100", "Supported Mode 01 PIDs 01–20"),
    ("0101", "Monitor status / MIL"),
    ("0902", "VIN"),
]


class App:
    """Interactive OBD CLI application."""

    def __init__(self, port: str, baud: int, timeout: float, dtc_db: Path):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self.db = load_dtc_db(dtc_db)
        self.session = ElmSession(port, baud, timeout)
        self.live_pids = list(DEFAULT_LIVE)
        self.profiles = ProfileStore()
        self._vehicle_info_cache: dict[str, str] | None = None

    @property
    def custom_pids(self) -> dict[str, dict]:
        """PIDs from the active make/vehicle profile only."""
        return self.profiles.pids

    @property
    def catalog(self) -> dict[str, tuple[str, str, object]]:
        """Built-in SAE PIDs plus customs from the active profile."""
        return {**PID_CATALOG, **customs_to_catalog(self.custom_pids)}

    # --- connection ---------------------------------------------------------

    def connect(self, quiet: bool = False) -> bool:
        try:
            info = self.session.open()
        except ConnectionError as exc:
            CONSOLE.print(f"[red]{exc}[/]")
            CONSOLE.print("[dim]./obdscan/connect-bt.sh[/]")
            return False
        self._vehicle_info_cache = None
        if not quiet:
            self.show_status()
            if not info.ecu_alive:
                CONSOLE.print(
                    "[yellow]No ECU yet[/] — normal on a bench supply. "
                    "DTCs/live data need a vehicle."
                )
            elif sys.stdin.isatty():
                self._offer_saved_map_on_connect()
        return True

    def disconnect(self) -> None:
        self.session.close()
        CONSOLE.print("[dim]Disconnected.[/]")

    def require_session(self) -> bool:
        if self.session.connected:
            return True
        CONSOLE.print("[cyan]Not connected — opening adapter…[/]")
        return self.connect()

    def show_status(self) -> None:
        info = self.session.info
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_row("Port", self.port)
        if info:
            table.add_row("ELM", info.version)
            table.add_row("Voltage", info.voltage or "—")
            table.add_row("Protocol", info.protocol or "—")
            table.add_row(
                "ECU",
                "[green]responding[/]" if info.ecu_alive else "[yellow]no response[/]",
            )
        else:
            table.add_row("Session", "[red]closed[/]")
        table.add_row("DTC table", f"{len(self.db)} generic codes")
        CONSOLE.print(Panel(table, title="Connection", border_style="cyan"))

    # --- modules ------------------------------------------------------------

    def module_read_codes(self, force: bool = False) -> None:
        rows = self._fetch_dtc_rows(force=force)
        if rows is None:
            return
        self._render_codes(rows)
        if sys.stdin.isatty() and Confirm.ask(
            "Save codes + vehicle info to Documents/Saved Codes?", default=False
        ):
            path = self._save_codes_report(rows)
            if path:
                CONSOLE.print(f"[green]Saved[/] → {path}")

    def module_save_codes(self, force: bool = False) -> None:
        """Read DTCs and vehicle info, then write a text report under Documents/Saved Codes."""
        rows = self._fetch_dtc_rows(force=force)
        if rows is None:
            return
        self._render_codes(rows)
        path = self._save_codes_report(rows)
        if path:
            CONSOLE.print(f"[green]Saved[/] → {path}")

    def module_clear_codes(self, yes: bool = False) -> None:
        if not self.require_session():
            return
        if not yes:
            if not sys.stdin.isatty():
                CONSOLE.print("[yellow]Refusing clear without --yes in non-interactive mode.[/]")
                return
            if not Confirm.ask(
                "[yellow]Clear stored DTCs and freeze-frame data?[/]", default=False
            ):
                CONSOLE.print("[dim]Cancelled.[/]")
                return
        resp = self.session.cmd("04", wait=2.0)
        cleaned = re.sub(r"\s", "", resp.upper())
        if "OK" in resp.upper() or "44" in cleaned:
            CONSOLE.print("[green]Clear command accepted.[/] Re-read codes to verify.")
        else:
            CONSOLE.print(Panel(resp or "(empty)", title="Response", border_style="yellow"))

    def module_live_data(
        self,
        once: bool = False,
        interval: float = 0.4,
        graph: bool | None = None,
        save_path: Path | None = None,
    ) -> None:
        if not self.require_session():
            return
        if not once and sys.stdin.isatty():
            self._offer_live_pid_edit()
            if not self._confirm_live_pid_load(self.live_pids):
                CONSOLE.print("[dim]Cancelled.[/]")
                return
        pids = self.live_pids
        if not pids:
            CONSOLE.print("[yellow]No live PIDs selected.[/] Use menu 7 or pass names on the CLI.")
            return
        if once:
            CONSOLE.print(self._live_table(pids))
            return
        if graph is None and sys.stdin.isatty():
            mode = Prompt.ask(
                "Display",
                choices=["table", "graph"],
                default="table",
            )
            graph = mode == "graph"
        elif graph is None:
            graph = False

        self._print_live_rate_hint(pids, interval)
        if graph:
            self._live_graph(pids, interval=interval, save_path=save_path)
        else:
            CONSOLE.print(
                f"[dim]PIDs: {', '.join(pids)}  ·  menu 7 to change  ·  Ctrl+C to stop[/]\n"
            )
            try:
                with Live(self._live_table(pids), console=CONSOLE, refresh_per_second=4) as live:
                    while True:
                        live.update(self._live_table(pids))
                        time.sleep(interval)
            except KeyboardInterrupt:
                CONSOLE.print("\n[dim]Live data stopped.[/]")

    def module_configure_live(self) -> None:
        CONSOLE.print(
            Panel(
                "Enter one or more PID names, separated by spaces or commas.\n"
                "Example: [bold]RPM THROTTLE STFT_B1 STFT_B2 O2_B1S1[/]\n"
                "Type [bold]list[/] to show the catalog, [bold]default[/] for the built-in set,\n"
                "or press Enter to keep the current selection.\n"
                "Custom PIDs (menu 9) can be typed by name once saved.\n\n"
                f"[dim]Currently ({len(self.live_pids)}): {' '.join(self.live_pids) or '(none)'}[/]",
                title="Live data PIDs",
                border_style="blue",
            )
        )
        while True:
            raw = Prompt.ask("PIDs", default=" ".join(self.live_pids))
            token = raw.strip().lower()
            if token in {"list", "ls", "?"}:
                self.module_pid_list()
                continue
            if token in {"default", "defaults", "reset"}:
                self.live_pids = list(DEFAULT_LIVE)
                CONSOLE.print(f"[green]Set:[/] {' '.join(self.live_pids)}")
                break
            if not raw.strip():
                CONSOLE.print(f"[dim]Unchanged:[/] {' '.join(self.live_pids) or '(none)'}")
                break
            chosen = self._parse_live_pid_names(raw)
            if not chosen:
                CONSOLE.print("[yellow]No valid PIDs — try again or type list.[/]")
                continue
            self.live_pids = chosen
            CONSOLE.print(f"[green]Set ({len(chosen)}):[/] {' '.join(chosen)}")
            self._warn_live_pid_count(chosen)
            break

    def _offer_live_pid_edit(self) -> None:
        CONSOLE.print(
            f"[cyan]Live PIDs[/] ({len(self.live_pids)}): "
            f"[bold]{' '.join(self.live_pids) or '(none)'}[/]"
        )
        if Confirm.ask("Change PID selection?", default=False):
            self.module_configure_live()

    def _parse_live_pid_names(self, raw: str) -> list[str]:
        chosen: list[str] = []
        seen: set[str] = set()
        for name in raw.replace(",", " ").split():
            key = name.strip().upper()
            if not key:
                continue
            if key not in self.catalog:
                CONSOLE.print(f"[yellow]Skip unknown:[/] {name}")
                continue
            if key in seen:
                continue
            seen.add(key)
            chosen.append(key)
        return chosen

    def _warn_live_pid_count(self, pids: list[str]) -> None:
        n = len(pids)
        if n < LIVE_PID_WARN_COUNT:
            return
        # Rough ELM round-trip budget; real cars vary a lot.
        est = n * 0.15
        CONSOLE.print(
            f"[yellow]Note:[/] {n} PIDs are queried one-by-one over ELM — "
            f"expect ~{est:.1f}s+ per refresh (plus your interval). "
            "Fewer PIDs = snappier live data / graphs."
        )

    def _confirm_live_pid_load(self, pids: list[str]) -> bool:
        self._warn_live_pid_count(pids)
        self._warn_if_foreign_custom_map()
        if len(pids) < LIVE_PID_CONFIRM_COUNT or not sys.stdin.isatty():
            return True
        return Confirm.ask(
            f"[yellow]{len(pids)} PIDs will update slowly. Continue?[/]",
            default=True,
        )

    def _warn_if_foreign_custom_map(self) -> None:
        """Surface cross-make / mismatched active profile before live use."""
        if not self.profiles.active_id:
            return
        customs_in_live = [p for p in self.live_pids if p in self.custom_pids]
        if not customs_in_live and not (self.profiles.active or {}).get("import_log"):
            # Still warn if entire active profile is wrong make for connected car
            pass
        vin = None
        if self.session.connected:
            try:
                vin = self._read_vin()
            except Exception:
                vin = None
        if vin:
            match = self.profiles.profile_matches_vin(self.profiles.active_id, vin)
            if match is False:
                make, _ = make_guess_from_vin(vin)
                cross = bool(
                    make
                    and make
                    not in [m.lower() for m in (self.profiles.active or {}).get("makes", [])]
                )
                if cross:
                    CONSOLE.print(
                        "[bold red]Live warning:[/] active profile is another make's map "
                        f"({self.profiles.active_id}). Custom values may be wrong."
                    )
                else:
                    CONSOLE.print(
                        f"[yellow]Live warning:[/] active profile {self.profiles.active_id} "
                        "does not match this vehicle's year/WMI."
                    )
        hints = (self.profiles.active or {}).get("vehicle_hints") or {}
        if hints.get("cross_make_import") and customs_in_live:
            src = hints.get("last_import_from") or "?"
            CONSOLE.print(
                f"[yellow]Note:[/] live set includes customs imported from another make "
                f"([bold]{src}[/]) — verify before trusting readings."
            )

    def _print_live_rate_hint(self, pids: list[str], interval: float) -> None:
        n = len(pids)
        if n < LIVE_PID_WARN_COUNT:
            return
        est = n * 0.15 + interval
        CONSOLE.print(
            f"[dim]Streaming {n} PIDs · rough cycle ≥ {est:.1f}s · "
            f"trim the set in menu 7 for faster updates[/]"
        )

    def module_vehicle_info(self) -> None:
        if not self.require_session():
            return
        info = self._collect_vehicle_info()
        table = Table(title="Vehicle / ECU info")
        table.add_column("Item", style="cyan")
        table.add_column("Value")
        for label, value in info.items():
            table.add_row(label, value)
        CONSOLE.print(table)

    def module_readiness(self) -> None:
        if not self.require_session():
            return
        resp = self.session.cmd("0101", wait=1.5)
        data = parse_mode01(resp, "01")
        if not data or len(data) < 4:
            CONSOLE.print("[yellow]No readiness data (need ECU).[/]")
            CONSOLE.print(Panel(resp, title="Raw", border_style="dim"))
            return
        a, b, c, d = data[0], data[1], data[2], data[3]
        mil_on = bool(a & 0x80)
        dtc_count = a & 0x7F
        table = Table(title="Monitor readiness (Mode 01 PID 01)")
        table.add_column("Monitor")
        table.add_column("Status")
        table.add_row("MIL", "[red]ON[/]" if mil_on else "[green]OFF[/]")
        table.add_row("DTC count", str(dtc_count))

        for name, available, incomplete in (
            ("Misfire", bool(b & 0x01), bool(b & 0x10)),
            ("Fuel system", bool(b & 0x02), bool(b & 0x20)),
            ("Components", bool(b & 0x04), bool(b & 0x40)),
        ):
            if not available:
                status = "[dim]n/a[/]"
            elif incomplete:
                status = "[yellow]incomplete[/]"
            else:
                status = "[green]ready[/]"
            table.add_row(name, status)

        spark = not bool(b & 0x08)
        for name, bit in (
            ("Catalyst", 0x01),
            ("Heated catalyst", 0x02),
            ("Evaporative system", 0x04),
            ("Secondary air", 0x08),
            ("A/C refrigerant", 0x10),
            ("Oxygen sensor", 0x20),
            ("Oxygen sensor heater", 0x40),
            ("EGR system", 0x80),
        ):
            supported = bool(c & bit)
            incomplete = bool(d & bit)
            if not supported:
                status = "[dim]n/a[/]"
            elif incomplete:
                status = "[yellow]incomplete[/]"
            else:
                status = "[green]ready[/]"
            table.add_row(name, status)

        CONSOLE.print(table)
        CONSOLE.print(f"[dim]Ignition type: {'spark' if spark else 'compression'}[/]")

    def module_freeze_frame(self) -> None:
        if not self.require_session():
            return
        # Mode 02 PID 02 = DTC that caused freeze frame; then sample common PIDs
        resp = self.session.cmd("0202", wait=1.5)
        CONSOLE.print(Panel(resp.strip() or "(empty)", title="Freeze frame DTC (02 02)", border_style="blue"))
        table = Table(title="Freeze frame sample (frame 00)")
        table.add_column("PID")
        table.add_column("Value")
        for name in ("RPM", "SPEED", "COOLANT", "LOAD", "THROTTLE"):
            pid = PID_CATALOG[name][0]
            raw = self.session.cmd(f"02{pid}00", wait=1.0)
            # Mode 02 responses start with 42
            hexes = [h.upper() for h in re.findall(r"[0-9A-Fa-f]{2}", raw)]
            val = "—"
            for i in range(len(hexes) - 3):
                if hexes[i] == "42" and hexes[i + 1] == pid.upper():
                    # skip frame byte sometimes
                    data = [int(h, 16) for h in hexes[i + 2 : i + 6]]
                    # if first data looks like frame 00, shift
                    if data and data[0] == 0 and len(hexes) > i + 3:
                        data = [int(h, 16) for h in hexes[i + 3 : i + 7]]
                    val = PID_CATALOG[name][2](data)
                    break
            table.add_row(name, val)
        CONSOLE.print(table)

    def module_lookup(self, codes: list[str] | None = None) -> None:
        if not codes:
            raw = Prompt.ask("Enter code(s)", default="P0420")
            codes = raw.replace(",", " ").split()
        table = Table(title="DTC lookup")
        table.add_column("Code", style="bold yellow")
        table.add_column("Description")
        for code in codes:
            table.add_row(code.strip().upper(), lookup_code(self.db, code))
        CONSOLE.print(table)

    def _show_raw_help(self) -> None:
        at = Table(title="AT commands (adapter)")
        at.add_column("Command", style="cyan")
        at.add_column("Description")
        for cmd, desc in RAW_AT_COMMANDS:
            at.add_row(cmd, desc)

        obd = Table(title="OBD commands (vehicle)")
        obd.add_column("Command", style="cyan")
        obd.add_column("Description")
        for cmd, desc in RAW_OBD_COMMANDS:
            obd.add_row(cmd, desc)
        for name, (pid, unit, _) in sorted(self.catalog.items()):
            tag = " custom" if name in self.custom_pids else ""
            obd.add_row(f"01{pid}", f"{name} ({unit}){tag}")

        CONSOLE.print(at)
        CONSOLE.print(obd)
        CONSOLE.print("[dim]Type any of the above, or another AT/OBD hex string, then Enter.[/]")

    def module_raw(self, command: str | None = None) -> None:
        if command and command.strip().lower() == "help":
            self._show_raw_help()
            return
        if not self.require_session():
            return
        while True:
            if not command:
                command = Prompt.ask(
                    "AT / OBD command (type help for command list)",
                    default="010C",
                )
            if command.strip().lower() == "help":
                self._show_raw_help()
                command = None
                continue
            break
        resp = self.session.cmd(command, wait=1.5)
        CONSOLE.print(Panel(resp.strip() or "(empty)", title=f"Raw · {command}", border_style="magenta"))

    def module_pid_list(self) -> None:
        cat = self.catalog
        rows = [
            (name, pid, unit, name in self.custom_pids)
            for name, (pid, unit, _) in sorted(
                cat.items(), key=lambda kv: (kv[1][0], kv[0])
            )
        ]
        mid = (len(rows) + 1) // 2

        def _half(title: str, chunk: list[tuple[str, str, str, bool]]) -> Table:
            table = Table(title=title, expand=True)
            table.add_column("Name", style="cyan", no_wrap=True)
            table.add_column("Mode 01", no_wrap=True)
            table.add_column("Unit", no_wrap=True)
            for name, pid, unit, custom in chunk:
                mark = "★" if name in self.live_pids else ""
                tag = " [magenta]cust[/]" if custom else ""
                table.add_row(f"{mark}{name}{tag}", f"01{pid}", unit or "—")
            return table

        CONSOLE.print(
            Panel(
                Columns(
                    [
                        _half(f"PIDs 1–{mid}", rows[:mid]),
                        _half(f"PIDs {mid + 1}–{len(rows)}", rows[mid:]),
                    ],
                    equal=True,
                    expand=True,
                ),
                title=(
                    f"Live PIDs ({len(PID_CATALOG)} SAE + {len(self.custom_pids)} "
                    f"custom@{self.profiles.active_id or 'none'})"
                ),
                border_style="blue",
            )
        )
        CONSOLE.print(
            "[dim]★ = selected for live · cust = user-defined (menu 9) · "
            "unsupported on a car → — / NO DATA[/]"
        )

    def module_enhanced(self) -> None:
        if interactive_enhanced_menu is None:
            CONSOLE.print(f"[red]Enhanced module failed to import:[/] {_IMPORT_ERR}")
            return
        interactive_enhanced_menu()

    def module_list_manufacturers(self) -> None:
        if interactive_enhanced_menu is None:
            CONSOLE.print(f"[red]Manufacturers failed to import:[/] {_IMPORT_ERR}")
            return
        show_manufacturer_list()

    # --- helpers ------------------------------------------------------------

    def _fetch_dtc_rows(self, force: bool = False) -> list[tuple[str, str]] | None:
        """Read stored/pending/permanent DTCs. Returns None if aborted."""
        if not self.require_session():
            return None
        info = self.session.info
        if info and not info.ecu_alive and not force:
            if sys.stdin.isatty():
                if not Confirm.ask("No ECU detected. Query DTCs anyway?", default=False):
                    return None
            else:
                CONSOLE.print(
                    "[yellow]No ECU detected.[/] Re-run with [bold]--force[/] to query anyway."
                )
                return None
        CONSOLE.print("[cyan]Reading DTCs[/] (stored / pending / permanent)…")
        rows: list[tuple[str, str]] = []
        for label, cmd in (("Stored", "03"), ("Pending", "07"), ("Permanent", "0A")):
            resp = self.session.cmd(cmd, wait=2.0)
            if any(x in resp.upper() for x in ("NO DATA", "UNABLE", "ERROR")):
                continue
            for code in parse_dtc_response(resp):
                rows.append((label, code))
        return rows

    def _collect_vehicle_info(self) -> dict[str, str]:
        """Gather VIN, MIL, a few PIDs, and adapter identity for display / save."""
        out: dict[str, str] = {}
        vin = self._read_vin()
        out["VIN"] = vin or "—"
        if vin:
            year = model_year_from_vin(vin)
            make, wmi = make_guess_from_vin(vin)
            if year is not None:
                out["Year"] = str(year)
            if make:
                out["Make"] = make
            if wmi:
                out["WMI"] = wmi
        mil = self._read_mil()
        out["MIL"] = mil or "—"
        for label, pid, unit, fmt in (
            ("Battery (PID 42)", "42", "V", PID_CATALOG["CTRL_MOD_V"][2]),
            ("Fuel level", "2F", "%", PID_CATALOG["FUEL_LEVEL"][2]),
            ("Runtime", "1F", "s", PID_CATALOG["RUNTIME"][2]),
        ):
            val = self._query_pid(pid, fmt)
            out[label] = f"{val} {unit}" if val != "—" else "—"
        for atcmd, label in (("ATI", "Adapter"), ("ATRV", "Voltage"), ("ATDP", "Protocol")):
            resp = self.session.cmd(atcmd, wait=0.5)
            line = next(
                (
                    ln.strip()
                    for ln in resp.splitlines()
                    if ln.strip() and ln.strip().upper() not in {atcmd, "OK", ">"}
                ),
                "—",
            )
            out[label] = line
        sess = self.session.info
        if sess:
            out["ELM"] = sess.version or "—"
            if sess.voltage and out.get("Voltage") in (None, "—"):
                out["Voltage"] = sess.voltage
            if sess.protocol and out.get("Protocol") in (None, "—"):
                out["Protocol"] = sess.protocol
        out["Port"] = self.port
        if self.profiles.active_id:
            out["Profile"] = self.profiles.active_id
        self._vehicle_info_cache = dict(out)
        return out

    def _vehicle_info_for_profile(self, *, force: bool = False) -> dict[str, str] | None:
        """Return cached or freshly collected vehicle info when a session is up."""
        if not self.session.connected:
            return None
        if force or not self._vehicle_info_cache:
            try:
                CONSOLE.print("[dim]Capturing working-car info (VIN, protocol, …)…[/]")
                return self._collect_vehicle_info()
            except Exception as exc:
                CONSOLE.print(f"[yellow]Could not read full vehicle info:[/] {exc}")
                vin = None
                try:
                    vin = self._read_vin()
                except Exception:
                    pass
                if not vin and self.session.info:
                    return {
                        "Protocol": self.session.info.protocol or "—",
                        "Port": self.port,
                    }
                if vin:
                    year = model_year_from_vin(vin)
                    make, wmi = make_guess_from_vin(vin)
                    return {
                        "VIN": vin,
                        **({"Year": str(year)} if year else {}),
                        **({"Make": make} if make else {}),
                        **({"WMI": wmi} if wmi else {}),
                        "Port": self.port,
                    }
                return None
        return dict(self._vehicle_info_cache)

    def _stamp_active_profile_vehicle(self, *, reason: str = "", force: bool = False) -> None:
        info = self._vehicle_info_for_profile(force=force)
        if not info:
            return
        self.profiles.record_working_vehicle(info, reason=reason or "save")

    def _save_codes_report(self, rows: list[tuple[str, str]]) -> Path | None:
        """Write DTC + vehicle info text file under Documents/Saved Codes."""
        CONSOLE.print("[cyan]Collecting vehicle info…[/]")
        vehicle = self._collect_vehicle_info()
        SAVED_CODES_DIR.mkdir(parents=True, exist_ok=True)

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vin = vehicle.get("VIN", "—")
        vin_part = ""
        if vin and vin != "—" and re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin.upper()):
            vin_part = f"_{vin.upper()}"
        path = SAVED_CODES_DIR / f"dtc_{stamp}{vin_part}.txt"

        lines: list[str] = [
            "obdscan — saved DTC report",
            f"Saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=== Vehicle ===",
        ]
        for label, value in vehicle.items():
            lines.append(f"{label}: {value}")
        lines.extend(["", "=== Diagnostic Trouble Codes ==="])
        if not rows:
            lines.append("(none reported)")
        else:
            lines.append(f"{'Type':<12} {'Code':<8} Description")
            lines.append("-" * 72)
            for bucket, code in rows:
                desc = lookup_code(self.db, code)
                lines.append(f"{bucket:<12} {code:<8} {desc}")
            lines.append("")
            lines.append(f"Total: {len(rows)} code(s)")

        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def _render_codes(self, rows: list[tuple[str, str]]) -> None:
        if not rows:
            CONSOLE.print(
                Panel(
                    "[green]No DTCs reported.[/]\n[dim]Clear MIL / no faults, or no ECU on the bus.[/]",
                    title="DTCs",
                    border_style="green",
                )
            )
            return
        table = Table(title="Diagnostic Trouble Codes")
        table.add_column("Type", style="cyan")
        table.add_column("Code", style="bold yellow")
        table.add_column("Description")
        for bucket, code in rows:
            table.add_row(bucket, code, lookup_code(self.db, code))
        CONSOLE.print(table)
        CONSOLE.print(f"[dim]{len(rows)} code(s) · {len(self.db)} generic definitions loaded[/]")

    def _query_pid(self, pid: str, fmt) -> str:
        resp = self.session.cmd(f"01{pid}", wait=1.0)
        data = parse_mode01(resp, pid)
        if not data:
            return "—"
        return fmt(data)

    def _query_pid_float(self, name: str) -> float | None:
        pid, _unit, fmt = self.catalog[name]
        text = self._query_pid(pid, fmt)
        if text == "—":
            return None
        try:
            return float(text)
        except ValueError:
            return None

    def _live_table(self, pids: list[str]) -> Table:
        table = Table(title="Live data", expand=False)
        table.add_column("PID", style="cyan")
        table.add_column("Value", style="bold")
        table.add_column("Unit")
        for name in pids:
            pid, unit, fmt = self.catalog[name]
            val = self._query_pid(pid, fmt)
            table.add_row(name, val, unit)
        return table

    def _live_graph(
        self,
        pids: list[str],
        interval: float = 0.4,
        save_path: Path | None = None,
    ) -> None:
        history: dict[str, deque[float | None]] = {
            name: deque(maxlen=GRAPH_HISTORY) for name in pids
        }
        samples: list[dict] = []
        CONSOLE.print(
            f"[dim]Graphing: {', '.join(pids)}  ·  Ctrl+C to stop"
            f"{' / auto-save on exit' if save_path else ''}[/]\n"
        )
        try:
            with Live(console=CONSOLE, refresh_per_second=4) as live:
                while True:
                    row: dict = {"t": time.time()}
                    for name in pids:
                        val = self._query_pid_float(name)
                        history[name].append(val)
                        row[name] = val
                    samples.append(row)
                    live.update(self._graph_renderable(pids, history))
                    time.sleep(interval)
        except KeyboardInterrupt:
            CONSOLE.print("\n[dim]Live graph stopped.[/]")

        if not samples:
            return
        if save_path is not None:
            paths = self._save_live_capture(pids, samples, history, save_path)
            for p in paths:
                CONSOLE.print(f"[green]Saved[/] → {p}")
            return
        if sys.stdin.isatty() and Confirm.ask(
            "Save graph series to Documents/Saved Codes?", default=True
        ):
            paths = self._save_live_capture(pids, samples, history)
            for p in paths:
                CONSOLE.print(f"[green]Saved[/] → {p}")

    def _graph_renderable(self, pids: list[str], history: dict[str, deque[float | None]]):
        panels = []
        for name in pids:
            unit = self.catalog[name][1]
            series = list(history[name])
            nums = [v for v in series if v is not None]
            last = nums[-1] if nums else None
            mn = min(nums) if nums else None
            mx = max(nums) if nums else None
            chart = self._ascii_chart(series, width=min(GRAPH_HISTORY, 64), height=GRAPH_HEIGHT)
            header = (
                f"{name} ({unit})  "
                f"last={last if last is not None else '—'}  "
                f"min={mn if mn is not None else '—'}  "
                f"max={mx if mx is not None else '—'}"
            )
            panels.append(Panel(chart, title=header, border_style="cyan", padding=(0, 1)))
        return Group(*panels)

    @staticmethod
    def _ascii_chart(series: list[float | None], width: int = 64, height: int = 8) -> str:
        """Render a rolling series as a simple terminal line chart."""
        if not series:
            return "[dim](waiting for samples…)[/]"
        # Pad / trim to width
        vals = list(series)[-width:]
        while len(vals) < width:
            vals.insert(0, None)
        nums = [v for v in vals if v is not None]
        if not nums:
            return "[dim](no numeric data yet)[/]"
        lo, hi = min(nums), max(nums)
        if hi <= lo:
            hi = lo + 1.0
        grid = [[" " for _ in range(width)] for _ in range(height)]
        prev_y: int | None = None
        for x, v in enumerate(vals):
            if v is None:
                prev_y = None
                continue
            y = int(round((height - 1) * (v - lo) / (hi - lo)))
            y = max(0, min(height - 1, y))
            # draw from bottom: row 0 is top
            row = height - 1 - y
            grid[row][x] = "●"
            if prev_y is not None:
                step = 1 if y > prev_y else -1
                for mid in range(prev_y + step, y, step):
                    grid[height - 1 - mid][x] = "│"
            prev_y = y
        lines = []
        for i, row in enumerate(grid):
            label = f"{hi:7.1f}" if i == 0 else (f"{lo:7.1f}" if i == height - 1 else " " * 7)
            lines.append(f"{label} │{''.join(row)}")
        lines.append(" " * 7 + " └" + "─" * width)
        return "\n".join(lines)

    def _save_live_capture(
        self,
        pids: list[str],
        samples: list[dict],
        history: dict[str, deque[float | None]],
        base: Path | None = None,
    ) -> list[Path]:
        """Write CSV time-series + ASCII chart snapshot under Saved Codes (or base path)."""
        SAVED_CODES_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if base is None:
            csv_path = SAVED_CODES_DIR / f"live_{stamp}.csv"
            txt_path = SAVED_CODES_DIR / f"live_{stamp}.txt"
        else:
            base = Path(base)
            if base.suffix.lower() == ".csv":
                csv_path = base
                txt_path = base.with_suffix(".txt")
            elif base.suffix.lower() == ".txt":
                txt_path = base
                csv_path = base.with_suffix(".csv")
            else:
                csv_path = base.with_name(base.name + ".csv") if base.suffix else Path(str(base) + ".csv")
                txt_path = csv_path.with_suffix(".txt")
            csv_path.parent.mkdir(parents=True, exist_ok=True)

        t0 = samples[0].get("t") or time.time()
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["elapsed_s", *pids])
            for row in samples:
                elapsed = (row.get("t") or t0) - t0
                writer.writerow(
                    [f"{elapsed:.3f}", *[row.get(p) if row.get(p) is not None else "" for p in pids]]
                )

        lines = [
            "obdscan — live graph capture",
            f"Saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Samples: {len(samples)}",
            f"PIDs: {', '.join(pids)}",
            "",
            "Re-open the .csv in a spreadsheet or plotter for a full chart.",
            "ASCII snapshot of the last window:",
            "",
        ]
        for name in pids:
            unit = self.catalog[name][1]
            series = list(history[name])
            lines.append(f"=== {name} ({unit}) ===")
            lines.append(self._ascii_chart(series, width=min(GRAPH_HISTORY, 64), height=GRAPH_HEIGHT))
            lines.append("")
        txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return [csv_path, txt_path]

    def _read_vin(self) -> str | None:
        # ISO 15765 multi-frame is messy on dumb ELM; try 0902 best-effort
        resp = self.session.cmd("0902", wait=2.5)
        ascii_chars = []
        hexes = re.findall(r"[0-9A-Fa-f]{2}", resp)
        for h in hexes:
            v = int(h, 16)
            if 32 <= v < 127:
                ascii_chars.append(chr(v))
        vin = "".join(ascii_chars)
        # VIN is 17 chars alphanumeric
        m = re.search(r"[A-HJ-NPR-Z0-9]{17}", vin.upper())
        return m.group(0) if m else (vin.strip() or None)

    def _read_mil(self) -> str | None:
        resp = self.session.cmd("0101", wait=1.2)
        data = parse_mode01(resp, "01")
        if not data:
            return None
        mil = "ON" if data[0] & 0x80 else "OFF"
        return f"{mil} ({data[0] & 0x7F} codes)"

    def module_custom_pids(self) -> None:
        """Make-scoped reverse-engineering store: profiles, scans, custom PIDs."""
        self._profile_autoload_from_vehicle()
        while True:
            CONSOLE.print()
            active = self.profiles.active
            if active:
                yf, yt = profile_years(active)
                active_label = (
                    f"{active['label']} [{self.profiles.active_id}] · "
                    f"{format_year_range(yf, yt)} · {len(self.custom_pids)} PIDs"
                )
            else:
                active_label = "(none — create/select a make+year profile)"
            table = Table(title="Custom PIDs · RE profiles", show_header=False, box=None, padding=(0, 2))
            table.add_row("[bold cyan]1[/]", "List / select make profiles")
            table.add_row("[bold cyan]2[/]", "Create profile (make + model years)")
            table.add_row("[bold cyan]3[/]", "Clone active profile → similar make/years")
            table.add_row(
                "[bold cyan]4[/]",
                "Import PIDs from another profile (starting point)",
            )
            table.add_row("[bold cyan]5[/]", "Edit active profile metadata (makes, years, WMI)")
            table.add_row("[bold cyan]6[/]", "List PIDs in active profile")
            table.add_row("[bold cyan]7[/]", "Add / define PID in active profile")
            table.add_row("[bold cyan]8[/]", "Remove PID from active profile")
            table.add_row("[bold cyan]9[/]", "Scan vehicle → save into active profile")
            table.add_row("[bold cyan]10[/]", "Add scanned hex PID into active profile")
            table.add_row("[bold cyan]11[/]", "Show recent scans for active profile")
            table.add_row("[bold cyan]12[/]", "Show / refresh working-car info on profile")
            table.add_row("[bold cyan]13[/]", "Export profile table + car info → Saved Codes")
            table.add_row("[bold cyan]14[/]", "Delete a profile")
            table.add_row("[bold cyan]b[/]", "Back")
            CONSOLE.print(Panel(table, border_style="magenta"))
            CONSOLE.print(f"[magenta]Active:[/] {active_label}")
            src = (active or {}).get("source_vehicle") or {}
            if src.get("VIN"):
                CONSOLE.print(
                    f"[dim]Built from:[/] VIN {src.get('VIN')}"
                    + (f" · {src.get('Make')}" if src.get("Make") else "")
                    + (f" · {src.get('Year')}" if src.get("Year") else "")
                    + (f" · {src.get('Protocol')}" if src.get("Protocol") else "")
                )
            CONSOLE.print(f"[dim]Store: {CUSTOM_PID_FILE}[/]")
            choice = Prompt.ask("Select", default="9").strip().lower()
            if choice in {"b", "back", "q"}:
                return
            handlers = {
                "1": self._profile_list_select,
                "2": self._profile_create,
                "3": self._profile_clone,
                "4": self._profile_import_pids,
                "5": self._profile_edit_meta,
                "6": self._custom_list,
                "7": self._custom_add,
                "8": self._custom_remove,
                "9": self._scan_vehicle_pids,
                "10": self._custom_add_from_hex,
                "11": self._profile_show_scans,
                "12": self._profile_show_vehicle,
                "13": self._profile_export_with_vehicle,
                "14": self._profile_delete,
            }
            fn = handlers.get(choice)
            if not fn:
                CONSOLE.print("[yellow]Unknown option[/]")
                continue
            try:
                fn()
            except (RuntimeError, ValueError) as exc:
                CONSOLE.print(f"[red]{exc}[/]")

    def _profile_banner_warn_vin(self, vin: str | None) -> None:
        if not vin or not self.profiles.active_id:
            return
        match = self.profiles.profile_matches_vin(self.profiles.active_id, vin)
        if match is False:
            year = model_year_from_vin(vin)
            yf, yt = profile_years(self.profiles.active or {})
            CONSOLE.print(
                f"[yellow]Warning:[/] VIN {vin}"
                + (f" ({year})" if year else "")
                + f" does not match active profile [bold]{self.profiles.active_id}[/] "
                f"(makes={self.profiles.active.get('makes')}, "
                f"years={format_year_range(yf, yt)}, "
                f"WMI={self.profiles.active.get('vin_wmi')}). "
                "Switch or create a make+year profile so customs stay scoped."
            )

    def _find_saved_map_exports(self, vin: str) -> list[Path]:
        """Exported profile JSON files under Saved Codes that include this VIN."""
        if not vin or not SAVED_CODES_DIR.is_dir():
            return []
        vin_u = vin.upper()
        hits: list[Path] = []
        for path in SAVED_CODES_DIR.glob("pid_profile_*.json"):
            name = path.name.upper()
            if vin_u in name:
                hits.append(path)
                continue
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            src = (raw.get("source_vehicle") or {}).get("VIN") or ""
            if str(src).upper() == vin_u:
                hits.append(path)
                continue
            for snap in raw.get("working_vehicles") or []:
                if str(snap.get("VIN") or "").upper() == vin_u:
                    hits.append(path)
                    break
        hits.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        return hits[:8]

    def _offer_saved_map_on_connect(self) -> None:
        """On connect, ask to load a saved PID map if this car has history."""
        try:
            vin = self._read_vin()
        except Exception:
            return
        if not vin:
            CONSOLE.print("[dim]No VIN — skip saved-map prompt.[/]")
            return

        make, _ = make_guess_from_vin(vin)
        year = model_year_from_vin(vin)
        CONSOLE.print(
            f"[cyan]Vehicle[/] VIN {vin}"
            + (f" · {make}" if make else "")
            + (f" · {year}" if year else "")
        )

        exact = self.profiles.profiles_for_exact_vin(vin)
        soft = self.profiles.profiles_matching_vin(vin)
        # Prefer exact-VIN history; fall back to make/year family maps
        candidates: list[tuple[str, str, int]] = list(exact)
        seen = {pid for pid, _, _ in candidates}
        for pid in soft:
            if pid in seen:
                continue
            prof = self.profiles.profiles.get(pid) or {}
            candidates.append(
                (pid, "make/year match", len(prof.get("pids") or {}))
            )
            seen.add(pid)

        if candidates:
            table = Table(title="Saved PID maps for this car", show_header=True)
            table.add_column("Id", style="cyan")
            table.add_column("Match")
            table.add_column("PIDs")
            table.add_column("Label")
            for pid, how, n in candidates:
                prof = self.profiles.profiles.get(pid) or {}
                mark = " ● active" if pid == self.profiles.active_id else ""
                table.add_row(pid + mark, how, str(n), str(prof.get("label") or pid))
            CONSOLE.print(table)

            default_id = candidates[0][0]
            if self.profiles.active_id in seen:
                active_n = len(self.custom_pids)
                if len(candidates) == 1:
                    CONSOLE.print(
                        f"[green]Saved map already loaded:[/] {self.profiles.active_id} "
                        f"({active_n} custom PIDs)"
                    )
                    return
                if not Confirm.ask(
                    f"Active map is [bold]{self.profiles.active_id}[/] "
                    f"({active_n} PIDs). Switch to another matching map?",
                    default=False,
                ):
                    return
            elif not Confirm.ask(
                f"Load saved PID map for this car"
                + (f" ([bold]{default_id}[/])" if len(candidates) == 1 else "")
                + "?",
                default=True,
            ):
                CONSOLE.print("[dim]Keeping current profile selection.[/]")
                self._profile_banner_warn_vin(vin)
                return

            choice = default_id
            if len(candidates) > 1:
                choice = Prompt.ask(
                    "Which profile id to load",
                    default=default_id,
                ).strip()
            target = slugify(choice)
            if target not in self.profiles.profiles:
                CONSOLE.print("[yellow]Unknown profile — not loaded.[/]")
                return
            # Cross-make soft matches still need confirm; exact VIN history is trusted
            exact_ids = {pid for pid, _, _ in exact}
            if target not in exact_ids and not self._confirm_activate_profile(target):
                return
            self.profiles.select(target)
            self._prune_live_pids_to_catalog()
            n = len(self.custom_pids)
            CONSOLE.print(
                f"[green]Loaded map[/] [bold]{target}[/] · {n} custom PID(s)"
            )
            return

        # No profile history — check Saved Codes exports
        exports = self._find_saved_map_exports(vin)
        if exports:
            CONSOLE.print(
                "[yellow]No in-app profile for this VIN, but found export file(s):[/]"
            )
            for p in exports[:5]:
                CONSOLE.print(f"  {p.name}")
            if Confirm.ask(
                "Import the newest export into a profile and load it?",
                default=True,
            ):
                self._import_profile_export(exports[0], vin=vin)
            return

        CONSOLE.print("[dim]No saved PID map history for this VIN yet.[/]")

    def _import_profile_export(self, path: Path, *, vin: str | None = None) -> None:
        """Load a Saved Codes pid_profile_*.json into the profile store and activate it."""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            CONSOLE.print(f"[red]Could not read export:[/] {exc}")
            return
        if not isinstance(raw, dict):
            CONSOLE.print("[red]Invalid export file.[/]")
            return
        base_id = slugify(str(raw.get("profile_id") or path.stem))
        profile_id = base_id
        n = 2
        while profile_id in self.profiles.profiles:
            profile_id = f"{base_id}_{n}"
            n += 1
        makes = raw.get("makes") or ([make_guess_from_vin(vin)[0]] if vin else [profile_id])
        makes = [slugify(str(m)) for m in makes if m]
        try:
            yf = raw.get("year_from")
            yt = raw.get("year_to")
            if yf is not None:
                yf = int(yf)
            if yt is not None:
                yt = int(yt)
        except (TypeError, ValueError):
            yf = yt = None
        if yf is None and vin:
            y = model_year_from_vin(vin)
            yf = yt = y
        self.profiles.create(
            profile_id,
            label=str(raw.get("label") or profile_id),
            makes=makes or [profile_id],
            vin_wmi=list(raw.get("vin_wmi") or []),
            year_from=yf,
            year_to=yt,
            notes=str(raw.get("notes") or f"Imported from {path.name}"),
            activate=True,
        )
        for name, spec in (raw.get("pids") or {}).items():
            try:
                self.profiles.set_pid(name, spec if isinstance(spec, dict) else {})
            except ValueError:
                continue
        src = raw.get("source_vehicle")
        if isinstance(src, dict) and src:
            self.profiles.record_working_vehicle(src, reason="import-export")
        elif vin:
            self.profiles.touch_vehicle_hints(vin=vin)
        self._prune_live_pids_to_catalog()
        CONSOLE.print(
            f"[green]Imported + loaded[/] [bold]{profile_id}[/] "
            f"from {path.name} · {len(self.custom_pids)} PID(s)"
        )

    def _profile_autoload_from_vehicle(self) -> None:
        """If connected, offer saved map / create profile for this VIN."""
        if not self.session.connected:
            return
        # Same prompt as connect (idempotent if already loaded)
        before = self.profiles.active_id
        self._offer_saved_map_on_connect()
        if self.profiles.active_id != before:
            return
        try:
            vin = self._read_vin()
        except Exception:
            return
        if not vin:
            return
        hits = self.profiles.profiles_matching_vin(vin) or [
            pid for pid, _, _ in self.profiles.profiles_for_exact_vin(vin)
        ]
        if hits:
            self._profile_banner_warn_vin(vin)
            return
        make, wmi = make_guess_from_vin(vin)
        year = model_year_from_vin(vin)
        year_mismatch = self.profiles.profiles_same_make_year_mismatch(vin)
        if year_mismatch and make and year:
            CONSOLE.print(
                f"[yellow]Same make, different years:[/] {', '.join(year_mismatch)} "
                f"— none cover {year}. Avoid reusing those PID tables."
            )
            if Confirm.ask(
                f"Create a new profile for [bold]{make} {year}[/]?",
                default=True,
            ):
                self._create_make_year_profile(make, year, wmi, vin)
                return
        if make:
            label_bits = f"{make}" + (f" {year}" if year else "")
            if Confirm.ask(
                f"No profile for this VIN. Create one for [bold]{label_bits}[/]?",
                default=True,
            ):
                self._create_make_year_profile(make, year, wmi, vin)
        self._profile_banner_warn_vin(vin)

    def _create_make_year_profile(
        self,
        make: str,
        year: int | None,
        wmi: str | None,
        vin: str | None,
    ) -> None:
        pid = f"{make}_{year}" if year else make
        label = f"{make.title()} {year}" if year else make.title()
        try:
            self.profiles.create(
                pid,
                label=label,
                makes=[make],
                vin_wmi=[wmi] if wmi else None,
                year_from=year,
                year_to=year,
                notes=f"Auto-created from VIN {vin}" if vin else "",
                activate=True,
            )
            CONSOLE.print(
                f"[green]Created profile[/] {slugify(pid)} "
                f"({format_year_range(year, year)})"
            )
            self._prune_live_pids_to_catalog()
        except ValueError as exc:
            CONSOLE.print(f"[yellow]{exc}[/]")
            if slugify(pid) in self.profiles.profiles:
                self.profiles.select(pid)
                self._prune_live_pids_to_catalog()
            elif make in self.profiles.profiles:
                self.profiles.select(make)
                self._prune_live_pids_to_catalog()

    def _prune_live_pids_to_catalog(self) -> None:
        """Drop live selections that are not in built-in + active profile."""
        cat = self.catalog
        before = list(self.live_pids)
        self.live_pids = [p for p in self.live_pids if p in cat]
        dropped = [p for p in before if p not in self.live_pids]
        if dropped:
            CONSOLE.print(
                f"[dim]Removed from live (other profile): {', '.join(dropped)}[/]"
            )

    def _profile_list_select(self) -> None:
        rows = self.profiles.list_summaries()
        if not rows:
            CONSOLE.print("[dim]No profiles yet — create one (option 2).[/]")
            return
        table = Table(title="Make / year profiles")
        table.add_column("")
        table.add_column("Id", style="cyan")
        table.add_column("Label")
        table.add_column("Years", style="green")
        table.add_column("PIDs")
        table.add_column("Makes")
        for pid, label, n, makes, years in rows:
            mark = "●" if pid == self.profiles.active_id else ""
            table.add_row(mark, pid, label, years, str(n), makes)
        CONSOLE.print(table)
        choice = Prompt.ask(
            "Activate profile id (Enter=keep)",
            default=self.profiles.active_id or "",
        ).strip()
        if not choice:
            return
        target = slugify(choice)
        if target not in self.profiles.profiles:
            CONSOLE.print("[yellow]Unknown profile id.[/]")
            return
        if not self._confirm_activate_profile(target):
            return
        if self.profiles.select(target):
            CONSOLE.print(f"[green]Active profile:[/] {self.profiles.active_id}")
            self._prune_live_pids_to_catalog()
        else:
            CONSOLE.print("[yellow]Unknown profile id.[/]")

    def _confirm_activate_profile(self, profile_id: str) -> bool:
        """Require explicit OK when activating a table that doesn't match this car."""
        prof = self.profiles.profiles.get(slugify(profile_id))
        if not prof:
            return False
        vin = None
        if self.session.connected:
            try:
                vin = self._read_vin()
            except Exception:
                vin = None
        if not vin:
            # Still warn if switching away from active to a different-make map
            if self.profiles.active_id and not self.profiles.makes_overlap(
                self.profiles.active_id, profile_id
            ):
                CONSOLE.print(
                    Panel(
                        f"Profile [bold]{profile_id}[/] is a [bold red]different make[/] "
                        f"({', '.join(prof.get('makes', []))}) than the current active "
                        f"({', '.join((self.profiles.active or {}).get('makes', []))}).\n\n"
                        "Using another make's PID table can show wrong values or miss data.\n"
                        "Prefer [bold]Import PIDs[/] (menu 4) into your make+year profile "
                        "as a starting point instead of activating the foreign table.",
                        title="Cross-make warning",
                        border_style="red",
                    )
                )
                return Confirm.ask(
                    "[red]Activate foreign make table anyway?[/]",
                    default=False,
                )
            return True
        match = self.profiles.profile_matches_vin(profile_id, vin)
        if match is not False:
            return True
        make, _ = make_guess_from_vin(vin)
        year = model_year_from_vin(vin)
        yf, yt = profile_years(prof)
        cross = bool(
            make
            and make not in [m.lower() for m in prof.get("makes", [])]
        )
        title = "Cross-make warning" if cross else "Profile mismatch"
        style = "red" if cross else "yellow"
        CONSOLE.print(
            Panel(
                f"Connected vehicle: VIN {vin}"
                + (f" · {make}" if make else "")
                + (f" · {year}" if year else "")
                + f"\nProfile [bold]{profile_id}[/]: makes={prof.get('makes')}, "
                f"years={format_year_range(yf, yt)}, WMI={prof.get('vin_wmi')}\n\n"
                + (
                    "[bold red]This is another make's map.[/] "
                    "Do not assume PIDs/formulas are valid on this car.\n"
                    "Safer: keep your make+year profile active and use "
                    "[bold]Import PIDs[/] (menu 4) as a starting point.\n"
                    if cross
                    else "Make may match but years/WMI do not — verify before relying on customs.\n"
                ),
                title=title,
                border_style=style,
            )
        )
        prompt = (
            "[red]Activate another make's table on this vehicle anyway?[/]"
            if cross
            else "[yellow]Activate mismatched profile anyway?[/]"
        )
        return Confirm.ask(prompt, default=False)

    def _profile_import_pids(self) -> None:
        """Copy another profile's PID table into the active make+year profile."""
        if not self.profiles.active_id:
            CONSOLE.print("[yellow]Create/select your make+year profile first (option 2/1).[/]")
            return
        rows = [r for r in self.profiles.list_summaries() if r[0] != self.profiles.active_id]
        if not rows:
            CONSOLE.print("[dim]No other profiles to import from.[/]")
            return
        dest = self.profiles.active
        dyf, dyt = profile_years(dest or {})
        CONSOLE.print(
            f"[magenta]Destination (active):[/] {self.profiles.active_id} · "
            f"makes={', '.join((dest or {}).get('makes', []))} · "
            f"years={format_year_range(dyf, dyt)} · "
            f"{len((dest or {}).get('pids', {}))} PIDs"
        )
        table = Table(title="Import source profiles")
        table.add_column("Id", style="cyan")
        table.add_column("Label")
        table.add_column("Years")
        table.add_column("PIDs")
        table.add_column("Makes")
        for pid, label, n, makes, years in rows:
            table.add_row(pid, label, years, str(n), makes)
        CONSOLE.print(table)
        src = Prompt.ask("Import PIDs from profile id").strip()
        if not src:
            return
        src_id = slugify(src)
        if src_id not in self.profiles.profiles:
            CONSOLE.print("[yellow]Unknown profile id.[/]")
            return
        src_prof = self.profiles.profiles[src_id]
        cross = not self.profiles.makes_overlap(src_id, self.profiles.active_id)
        if cross:
            CONSOLE.print(
                Panel(
                    f"You are about to load [bold]{src_id}[/] "
                    f"({', '.join(src_prof.get('makes', []))}) into "
                    f"[bold]{self.profiles.active_id}[/] "
                    f"({', '.join((dest or {}).get('makes', []))}).\n\n"
                    "[bold red]Cross-make import[/] — treat this only as a "
                    "starting point. Formulas/PIDs may be wrong for this car. "
                    "Verify each PID against a live scan before trusting values.\n"
                    "Imported entries are tagged [from:…] in their notes.",
                    title="Warning · other make's table",
                    border_style="red",
                )
            )
            if not Confirm.ask(
                "[red]Import another make's PID map as a starting point?[/]",
                default=False,
            ):
                CONSOLE.print("[dim]Cancelled.[/]")
                return
        else:
            CONSOLE.print(
                f"[dim]Same-make import from {src_id} → {self.profiles.active_id}[/]"
            )
            if not Confirm.ask("Proceed with import?", default=True):
                return
        mode = Prompt.ask(
            "Mode: [m]erge (keep existing) / [r]eplace (wipe active PIDs first)",
            default="m",
        ).strip().lower()
        replace = mode.startswith("r")
        if replace and (dest or {}).get("pids"):
            if not Confirm.ask(
                f"[yellow]Replace will delete {len(dest['pids'])} existing PID(s) "
                f"in {self.profiles.active_id}. Continue?[/]",
                default=False,
            ):
                return
        result = self.profiles.import_pids(src_id, replace=replace)
        self._prune_live_pids_to_catalog()
        msg = (
            f"[green]Imported[/] {result['copied']} new"
            + (f", skipped {result['skipped']} existing" if result["skipped"] else "")
            + (f", replaced {result['replaced']}" if result["replaced"] else "")
            + f" from [bold]{result['src']}[/] → [bold]{result['dest']}[/]"
            f" ({result['total_src']} in source)"
        )
        CONSOLE.print(msg)
        if result["cross_make"]:
            CONSOLE.print(
                "[yellow]Reminder:[/] cross-make map loaded — verify against this "
                "vehicle before using live data."
            )

    def _profile_create(self) -> None:
        vin = None
        if self.session.connected:
            vin = self._read_vin()
        make_guess, wmi = make_guess_from_vin(vin)
        year = model_year_from_vin(vin)
        default_id = f"{make_guess}_{year}" if make_guess and year else (make_guess or "my_make")
        profile_id = Prompt.ask("Profile id (slug)", default=default_id).strip()
        default_label = (
            f"{(make_guess or profile_id).replace('_', ' ').title()}"
            + (f" {year}" if year else "")
        )
        label = Prompt.ask("Label", default=default_label)
        makes_raw = Prompt.ask(
            "Makes covered (comma/space)",
            default=make_guess or profile_id,
        )
        makes = [slugify(m) for m in makes_raw.replace(",", " ").split() if m.strip()]
        year_default = str(year) if year else ""
        year_raw = Prompt.ask(
            "Model years (2018, 2018-2022, 2018+, or blank=any)",
            default=year_default,
        )
        try:
            year_from, year_to = parse_year_range(year_raw)
        except ValueError as exc:
            CONSOLE.print(f"[red]{exc}[/]")
            return
        wmi_raw = Prompt.ask(
            "VIN WMI prefixes to bind (3-letter, optional)",
            default=wmi or "",
        )
        wmis = [w.strip().upper()[:3] for w in wmi_raw.replace(",", " ").split() if w.strip()]
        notes = Prompt.ask("Notes", default="")
        try:
            self.profiles.create(
                profile_id,
                label=label,
                makes=makes or [slugify(profile_id)],
                vin_wmi=wmis or None,
                year_from=year_from,
                year_to=year_to,
                notes=notes,
                activate=True,
            )
        except ValueError as exc:
            CONSOLE.print(f"[red]{exc}[/]")
            return
        if vin:
            self.profiles.touch_vehicle_hints(
                vehicle=self._vehicle_info_for_profile() or {"VIN": vin}
            )
        CONSOLE.print(
            f"[green]Created + activated[/] {slugify(profile_id)} "
            f"years={format_year_range(year_from, year_to)}"
        )
        self._prune_live_pids_to_catalog()

    def _profile_clone(self) -> None:
        if not self.profiles.active_id:
            CONSOLE.print("[yellow]Nothing to clone — create a profile first.[/]")
            return
        src = self.profiles.active
        yf, yt = profile_years(src or {})
        dest = Prompt.ask(
            f"New profile id (clone of {self.profiles.active_id})",
            default=f"{self.profiles.active_id}_v2",
        ).strip()
        label = Prompt.ask("Label", default=dest.replace("_", " ").title())
        try:
            self.profiles.clone(self.profiles.active_id, dest, label=label)
        except ValueError as exc:
            CONSOLE.print(f"[red]{exc}[/]")
            return
        dest_id = slugify(dest)
        year_raw = Prompt.ask(
            "Years for clone (change if platform years differ)",
            default=format_year_range(yf, yt) if (yf or yt) else "",
        )
        try:
            nyf, nyt = parse_year_range(year_raw)
            self.profiles.profiles[dest_id]["year_from"] = nyf
            self.profiles.profiles[dest_id]["year_to"] = nyt
            self.profiles.save()
        except ValueError as exc:
            CONSOLE.print(f"[yellow]Kept source years — {exc}[/]")
        if Confirm.ask(f"Activate {dest_id} now?", default=True):
            self.profiles.select(dest_id)
            self._prune_live_pids_to_catalog()
        CONSOLE.print(
            f"[green]Cloned[/] → {dest_id} "
            f"(edit makes/years/WMI if this is a different generation)"
        )

    def _profile_edit_meta(self) -> None:
        prof = self.profiles.active
        if not prof:
            CONSOLE.print("[yellow]No active profile.[/]")
            return
        yf, yt = profile_years(prof)
        CONSOLE.print(
            Panel(
                f"id={prof['id']}\nlabel={prof.get('label')}\n"
                f"makes={', '.join(prof.get('makes', []))}\n"
                f"years={format_year_range(yf, yt)}\n"
                f"vin_wmi={', '.join(prof.get('vin_wmi', []))}\n"
                f"notes={prof.get('notes') or '—'}",
                title="Active profile",
                border_style="magenta",
            )
        )
        prof["label"] = Prompt.ask("Label", default=prof.get("label", prof["id"]))
        makes_raw = Prompt.ask("Makes", default=" ".join(prof.get("makes", [])))
        prof["makes"] = [slugify(m) for m in makes_raw.replace(",", " ").split() if m.strip()]
        year_raw = Prompt.ask(
            "Years (2018, 2018-2022, 2018+, blank=any)",
            default=format_year_range(yf, yt) if (yf is not None or yt is not None) else "",
        )
        try:
            prof["year_from"], prof["year_to"] = parse_year_range(year_raw)
        except ValueError as exc:
            CONSOLE.print(f"[red]{exc}[/]")
            return
        wmi_raw = Prompt.ask("VIN WMIs", default=" ".join(prof.get("vin_wmi", [])))
        prof["vin_wmi"] = [w.strip().upper()[:3] for w in wmi_raw.replace(",", " ").split() if w.strip()]
        prof["notes"] = Prompt.ask("Notes", default=prof.get("notes") or "")
        self.profiles.save()
        CONSOLE.print("[green]Profile metadata saved.[/]")

    def _profile_delete(self) -> None:
        rows = self.profiles.list_summaries()
        if not rows:
            CONSOLE.print("[dim]No profiles.[/]")
            return
        for pid, label, n, makes, years in rows:
            CONSOLE.print(f"  {pid} — {label} ({n} PIDs) [{makes}] years={years}")
        target = Prompt.ask("Profile id to delete").strip()
        if not target:
            return
        if not Confirm.ask(f"[yellow]Delete profile {slugify(target)}?[/]", default=False):
            return
        if self.profiles.delete(target):
            CONSOLE.print("[green]Deleted.[/]")
            self._prune_live_pids_to_catalog()
        else:
            CONSOLE.print("[yellow]Not found.[/]")

    def _profile_show_scans(self) -> None:
        prof = self.profiles.active
        if not prof:
            CONSOLE.print("[yellow]No active profile.[/]")
            return
        scans = prof.get("scans") or []
        if not scans:
            CONSOLE.print("[dim]No saved scans for this profile yet.[/]")
            return
        for i, scan in enumerate(reversed(scans[-10:]), 1):
            hits = scan.get("hits") or []
            unlisted = [h for h in hits if h.get("unlisted")]
            CONSOLE.print(
                f"[cyan]{i}.[/] {scan.get('saved')}  VIN={scan.get('vin') or '—'}  "
                f"year={scan.get('year') or '—'}  "
                f"hits={len(hits)} unlisted={len(unlisted)}  "
                f"{'deep ' if scan.get('deep') else ''}"
                f"proto={scan.get('protocol') or '—'}"
            )
            veh = scan.get("vehicle") or {}
            if veh:
                extras = [
                    f"{k}={v}"
                    for k, v in veh.items()
                    if k not in {"VIN", "vin", "Year", "Protocol", "recorded", "reason"}
                    and v not in (None, "", "—")
                ]
                if extras:
                    CONSOLE.print(f"     [dim]{', '.join(extras[:6])}[/]")
            for h in unlisted[:8]:
                CONSOLE.print(
                    f"     01{h.get('pid')}  {h.get('status')}  {h.get('sample')}"
                )

    def _profile_show_vehicle(self) -> None:
        if not self._require_active_profile():
            return
        prof = self.profiles.active or {}
        src = prof.get("source_vehicle") or {}
        if self.session.connected and Confirm.ask(
            "Refresh from connected car now?",
            default=not bool(src),
        ):
            self._stamp_active_profile_vehicle(reason="manual-refresh", force=True)
            src = (self.profiles.active or {}).get("source_vehicle") or {}
        if not src:
            CONSOLE.print(
                "[dim]No working-car info on this profile yet. "
                "Connect and scan/add a PID, or refresh above.[/]"
            )
            return
        table = Table(title=f"Working car · {self.profiles.active_id}")
        table.add_column("Field", style="cyan")
        table.add_column("Value")
        for k, v in src.items():
            table.add_row(str(k), str(v))
        CONSOLE.print(table)
        hist = prof.get("working_vehicles") or []
        if len(hist) > 1:
            CONSOLE.print(f"[dim]{len(hist)} vehicle snapshots on this profile[/]")
            for snap in hist[-5:]:
                CONSOLE.print(
                    f"  [dim]{snap.get('recorded', '?')}  "
                    f"VIN={snap.get('VIN', '—')}  "
                    f"{snap.get('Make', '')} {snap.get('Year', '')}  "
                    f"{snap.get('reason', '')}[/]"
                )

    def _profile_export_with_vehicle(self) -> None:
        """Write active profile PID table + working-car info under Saved Codes."""
        if not self._require_active_profile():
            return
        if self.session.connected:
            self._stamp_active_profile_vehicle(reason="export", force=False)
        prof = self.profiles.active or {}
        src = prof.get("source_vehicle") or prof.get("vehicle_hints") or {}
        SAVED_CODES_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vin = str(src.get("VIN") or src.get("last_vin") or "")
        vin_part = f"_{vin}" if re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin.upper()) else ""
        pid = self.profiles.active_id
        base = SAVED_CODES_DIR / f"pid_profile_{pid}{vin_part}_{stamp}"
        txt_path = Path(str(base) + ".txt")
        json_path = Path(str(base) + ".json")

        lines = [
            "obdscan — custom PID profile export",
            f"Saved: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Profile: {pid}",
            f"Label: {prof.get('label', pid)}",
            f"Makes: {', '.join(prof.get('makes', []))}",
            f"Years: {format_year_range(*profile_years(prof))}",
            f"WMI: {', '.join(prof.get('vin_wmi', [])) or '—'}",
            "",
            "=== Working car (source) ===",
        ]
        if src:
            for k, v in src.items():
                lines.append(f"{k}: {v}")
        else:
            lines.append("(none recorded — connect to a car when saving PIDs/scans)")
        lines.extend(["", "=== Custom PIDs ==="])
        pids = prof.get("pids") or {}
        if not pids:
            lines.append("(none)")
        else:
            lines.append(f"{'Name':<16} {'PID':<6} {'Unit':<8} {'Formula':<12} Note")
            lines.append("-" * 72)
            for name, spec in sorted(pids.items()):
                formula = spec.get("formula", "raw")
                note = spec.get("note") or ""
                vin_tag = spec.get("saved_with_vin") or ""
                if vin_tag and vin_tag not in note:
                    note = f"{note} vin={vin_tag}".strip()
                lines.append(
                    f"{name:<16} 01{spec.get('pid', '??'):<4} "
                    f"{(spec.get('unit') or '—'):<8} {formula:<12} {note}"
                )
        txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        payload = {
            "exported": datetime.now().isoformat(timespec="seconds"),
            "profile_id": pid,
            "label": prof.get("label"),
            "makes": prof.get("makes"),
            "year_from": prof.get("year_from"),
            "year_to": prof.get("year_to"),
            "vin_wmi": prof.get("vin_wmi"),
            "notes": prof.get("notes"),
            "source_vehicle": prof.get("source_vehicle"),
            "working_vehicles": prof.get("working_vehicles"),
            "pids": pids,
            "scans": (prof.get("scans") or [])[-5:],
            "import_log": (prof.get("import_log") or [])[-5:],
        }
        json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        CONSOLE.print(f"[green]Exported[/] → {txt_path}")
        CONSOLE.print(f"[green]Exported[/] → {json_path}")

    def _require_active_profile(self) -> bool:
        if self.profiles.active:
            return True
        CONSOLE.print("[yellow]Create or select a make profile first (options 1–2).[/]")
        return False

    def _custom_list(self) -> None:
        if not self._require_active_profile():
            return
        if not self.custom_pids:
            CONSOLE.print(
                f"[dim]No custom PIDs in profile {self.profiles.active_id} yet.[/]"
            )
            return
        table = Table(title=f"Custom PIDs · {self.profiles.active_id}")
        table.add_column("Name", style="cyan")
        table.add_column("Mode 01")
        table.add_column("Unit")
        table.add_column("Formula")
        table.add_column("Note")
        for name, spec in sorted(self.custom_pids.items()):
            formula = spec.get("formula", "raw")
            if formula == "scale":
                formula = f"scale×{spec.get('mult', 1)}+{spec.get('offset', 0)}"
                if spec.get("wide"):
                    formula += " (A:B)"
            table.add_row(
                name,
                f"01{spec['pid']}",
                spec.get("unit") or "—",
                formula,
                spec.get("note") or "",
            )
        CONSOLE.print(table)
        src = (self.profiles.active or {}).get("source_vehicle") or {}
        if src.get("VIN"):
            CONSOLE.print(
                f"[dim]Source car: VIN {src.get('VIN')}"
                + (f" · {src.get('Make')}" if src.get("Make") else "")
                + (f" · {src.get('Year')}" if src.get("Year") else "")
                + "[/]"
            )
        log = (self.profiles.active or {}).get("import_log") or []
        if log:
            last = log[-1]
            tag = " [cross-make]" if last.get("cross_make") else ""
            CONSOLE.print(
                f"[dim]Last import:{tag} from {last.get('from')} at {last.get('at')} "
                f"({last.get('mode')}, +{last.get('copied', 0)})[/]"
            )
        CONSOLE.print(table)

    def _custom_add(self) -> None:
        if not self._require_active_profile():
            return
        name = Prompt.ask("Name (letters/numbers/_)", default="CUSTOM_01").strip().upper()
        name = re.sub(r"[^A-Z0-9_]", "_", name)
        if not name:
            CONSOLE.print("[yellow]Cancelled.[/]")
            return
        if name in PID_CATALOG:
            CONSOLE.print("[yellow]That name is reserved by a built-in SAE PID.[/]")
            return
        pid = Prompt.ask("Mode 01 PID hex (2 digits)", default="0B").strip().upper()
        if not re.fullmatch(r"[0-9A-F]{2}", pid):
            CONSOLE.print("[red]PID must be exactly 2 hex digits (e.g. 0C).[/]")
            return
        unit = Prompt.ask("Unit label (optional)", default="")
        CONSOLE.print("Formulas: " + ", ".join(f"{k}={v}" for k, v in FORMULA_HELP.items()))
        formula = Prompt.ask("Formula", default="raw", choices=sorted(FORMULA_HELP)).strip().lower()
        mult, offset, wide = 1.0, 0.0, False
        if formula == "scale":
            wide = Confirm.ask("Use 16-bit A:B instead of single byte A?", default=False)
            try:
                mult = float(Prompt.ask("Multiplier", default="1"))
                offset = float(Prompt.ask("Offset", default="0"))
            except ValueError:
                CONSOLE.print("[red]Invalid mult/offset.[/]")
                return
        note = Prompt.ask("Note (optional)", default="")
        vehicle = self._vehicle_info_for_profile()
        self.profiles.set_pid(
            name,
            {
                "pid": pid,
                "unit": unit,
                "formula": formula,
                "mult": mult,
                "offset": offset,
                "wide": wide,
                "note": note,
            },
            vehicle=vehicle,
        )
        CONSOLE.print(
            f"[green]Saved[/] {name} → 01{pid} in profile [bold]{self.profiles.active_id}[/]"
        )
        if vehicle and vehicle.get("VIN") not in (None, "—"):
            CONSOLE.print(f"[dim]Recorded working car VIN {vehicle['VIN']} on profile[/]")
        if Confirm.ask("Add to live PID selection now?", default=True):
            if name not in self.live_pids:
                self.live_pids.append(name)
            CONSOLE.print(f"[dim]Live:[/] {' '.join(self.live_pids)}")

    def _custom_add_from_hex(self) -> None:
        if not self._require_active_profile():
            return
        pid = Prompt.ask("PID hex from scan (2 digits)", default="").strip().upper()
        if not re.fullmatch(r"[0-9A-F]{2}", pid):
            CONSOLE.print("[yellow]Need a 2-digit hex PID.[/]")
            return
        default_name = f"PID_{pid}"
        name = Prompt.ask("Name", default=default_name).strip().upper()
        name = re.sub(r"[^A-Z0-9_]", "_", name)
        if name in PID_CATALOG:
            CONSOLE.print("[yellow]Name clashes with built-in — pick another.[/]")
            return
        unit = Prompt.ask("Unit (optional)", default="")
        formula = Prompt.ask("Formula", default="raw", choices=sorted(FORMULA_HELP)).strip().lower()
        vehicle = self._vehicle_info_for_profile()
        self.profiles.set_pid(
            name,
            {
                "pid": pid,
                "unit": unit,
                "formula": formula,
                "mult": 1.0,
                "offset": 0.0,
                "wide": False,
                "note": f"from vehicle scan · profile {self.profiles.active_id}",
            },
            vehicle=vehicle,
        )
        CONSOLE.print(
            f"[green]Saved[/] {name} → 01{pid} in [bold]{self.profiles.active_id}[/]"
        )
        if vehicle and vehicle.get("VIN") not in (None, "—"):
            CONSOLE.print(f"[dim]Recorded working car VIN {vehicle['VIN']} on profile[/]")
        if Confirm.ask("Add to live selection?", default=True):
            if name not in self.live_pids:
                self.live_pids.append(name)

    def _custom_remove(self) -> None:
        if not self._require_active_profile():
            return
        if not self.custom_pids:
            CONSOLE.print("[dim]Nothing to remove.[/]")
            return
        self._custom_list()
        name = Prompt.ask("Name to remove").strip().upper()
        if not self.profiles.remove_pid(name):
            CONSOLE.print("[yellow]Not found in active profile.[/]")
            return
        self.live_pids = [p for p in self.live_pids if p != name]
        CONSOLE.print(f"[green]Removed[/] {name} from {self.profiles.active_id}")

    def _scan_vehicle_pids(self) -> None:
        """Use SAE Mode 01 support bitmaps, then probe for live-looking responses."""
        if not self.require_session():
            return
        if not self._require_active_profile():
            return
        vin = self._read_vin()
        self._profile_banner_warn_vin(vin)
        protocol = None
        if self.session.info:
            protocol = self.session.info.protocol
        CONSOLE.print(
            f"[cyan]Scanning into profile [bold]{self.profiles.active_id}[/][/] "
            "(0100 / 0120 / …), then probing each supported PID…"
        )
        known_hex = catalog_hex_set(PID_CATALOG)
        custom_hex = {spec["pid"] for spec in self.custom_pids.values()}
        supported: list[int] = []
        base = 0x00
        for _ in range(8):
            pid_hex = f"{base:02X}"
            resp = self.session.cmd(f"01{pid_hex}", wait=1.2)
            data = parse_mode01(resp, pid_hex)
            if not data or len(data) < 4:
                CONSOLE.print(f"[dim]No support bitmap at 01{pid_hex} — stop.[/]")
                break
            block, more = decode_support_bitfield(base, data)
            supported.extend(block)
            if not more:
                break
            base += 0x20
        seen: set[int] = set()
        value_pids = []
        for p in supported:
            if p in seen or (p % 0x20 == 0):
                continue
            seen.add(p)
            value_pids.append(p)

        table = Table(
            title=(
                f"Scan · {self.profiles.active_id} · "
                f"{len(value_pids)} supported value PIDs"
            )
        )
        table.add_column("PID")
        table.add_column("Status")
        table.add_column("Sample")
        table.add_column("Notes")

        hits: list[dict] = []
        unlisted_hits: list[str] = []
        for num in value_pids:
            hx = f"{num:02X}"
            resp = self.session.cmd(f"01{hx}", wait=0.8)
            data = parse_mode01(resp, hx)
            up = resp.upper()
            unlisted = hx not in known_hex
            if data is None or "NO DATA" in up or "UNABLE" in up or "ERROR" in up:
                status = "no data"
                sample = "—"
                note = ""
            else:
                sample = " ".join(f"{b:02X}" for b in data)
                if all(b == 0 for b in data):
                    status = "zero"
                    note = "responds but all zero"
                else:
                    status = "data"
                    note = ""
                if unlisted:
                    note = (note + " · " if note else "") + "not in built-in list"
                    unlisted_hits.append(hx)
                elif hx in custom_hex:
                    note = (note + " · " if note else "") + "in this profile"
                else:
                    names = [n for n, (p, _, _) in PID_CATALOG.items() if p == hx]
                    note = (note + " · " if note else "") + ",".join(names[:2])
            style_status = {
                "data": "[green]data[/]",
                "zero": "[dim]zero[/]",
                "no data": "[yellow]no data[/]",
            }.get(status, status)
            table.add_row(f"01{hx}", style_status, sample, note)
            hits.append(
                {
                    "pid": hx,
                    "status": status,
                    "sample": sample,
                    "unlisted": unlisted and status in {"data", "zero"},
                }
            )

        CONSOLE.print(table)
        if unlisted_hits:
            CONSOLE.print(
                f"[magenta]Unlisted with response:[/] "
                + ", ".join(f"01{h}" for h in unlisted_hits)
            )
            CONSOLE.print(
                "[dim]Option 9 adds one into this make profile "
                "(start with formula=raw, refine later).[/]"
            )
        else:
            CONSOLE.print(
                "[dim]No supported PIDs outside the built-in catalog "
                "(or none with data).[/]"
            )

        deep = Confirm.ask(
            "Also brute-probe 01–FF for responses not in support bits? (slow)",
            default=False,
        )
        deep_hits: list[dict] = []
        if deep:
            deep_hits = self._scan_deep_pids(
                set(value_pids) | {0x00, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0}
            )
            hits.extend(deep_hits)

        if Confirm.ask("Save this scan into the active make profile?", default=True):
            vehicle = self._vehicle_info_for_profile(force=True)
            if vehicle is None:
                vehicle = {"VIN": vin or "", "Protocol": protocol or "", "Port": self.port}
            elif vin and vehicle.get("VIN") in (None, "—"):
                vehicle["VIN"] = vin
            self.profiles.add_scan(
                hits, vin=vin, protocol=protocol, deep=deep, vehicle=vehicle
            )
            CONSOLE.print(
                f"[green]Scan saved[/] under profile [bold]{self.profiles.active_id}[/]"
                + (
                    f" · VIN {vehicle.get('VIN')}"
                    if vehicle.get("VIN") not in (None, "", "—")
                    else ""
                )
            )
            if Confirm.ask(
                "Also export profile table + car info to Documents/Saved Codes?",
                default=False,
            ):
                self._profile_export_with_vehicle()

    def _scan_deep_pids(self, skip: set[int]) -> list[dict]:
        CONSOLE.print("[cyan]Deep probe[/] — this can take a minute…")
        known_hex = catalog_hex_set(PID_CATALOG)
        found: list[dict] = []
        for num in range(0x01, 0x100):
            if num in skip or num % 0x20 == 0:
                continue
            hx = f"{num:02X}"
            resp = self.session.cmd(f"01{hx}", wait=0.35)
            data = parse_mode01(resp, hx)
            if not data or all(b == 0 for b in data):
                continue
            sample = " ".join(f"{b:02X}" for b in data)
            unlisted = hx not in known_hex
            tag = "unlisted" if unlisted else "listed"
            found.append(
                {
                    "pid": hx,
                    "status": "data",
                    "sample": sample,
                    "unlisted": unlisted,
                    "deep": True,
                }
            )
            CONSOLE.print(f"  [green]01{hx}[/] → {sample} [dim]{tag}[/]")
        if not found:
            CONSOLE.print("[dim]Deep probe found nothing extra.[/]")
        else:
            extras = [h["pid"] for h in found if h.get("unlisted")]
            if extras:
                CONSOLE.print(
                    "[magenta]Extra unlisted responses:[/] "
                    + ", ".join(f"01{h}" for h in extras)
                )
        return found

    # --- interactive menu ---------------------------------------------------

    def menu(self) -> None:
        self._banner()
        if not self.session.connected:
            if Confirm.ask(f"Connect to [bold]{self.port}[/] now?", default=True):
                self.connect()

        actions = {
            "1": ("Connection status", lambda: self.show_status()),
            "2": ("Connect / reconnect", lambda: self.connect()),
            "3": ("Disconnect", lambda: self.disconnect()),
            "4": ("Read codes (DTCs)", lambda: self.module_read_codes()),
            "5": ("Clear codes", lambda: self.module_clear_codes()),
            "6": ("Live data", lambda: self.module_live_data()),
            "7": ("Configure live PIDs", lambda: self.module_configure_live()),
            "8": ("List available PIDs", lambda: self.module_pid_list()),
            "9": ("Custom PIDs / RE profiles (per make)", lambda: self.module_custom_pids()),
            "10": ("Vehicle info", lambda: self.module_vehicle_info()),
            "11": ("Readiness / MIL", lambda: self.module_readiness()),
            "12": ("Freeze frame", lambda: self.module_freeze_frame()),
            "13": ("Lookup code(s)", lambda: self.module_lookup()),
            "14": ("Raw AT/OBD command", lambda: self.module_raw()),
            "15": ("Enhanced DoIP / manufacturer modules", lambda: self.module_enhanced()),
            "16": ("List manufacturer libraries", lambda: self.module_list_manufacturers()),
            "17": ("Save codes + vehicle info", lambda: self.module_save_codes()),
            "q": ("Quit", None),
        }

        while True:
            CONSOLE.print()
            table = Table(title="obdscan modules", show_header=False, box=None, padding=(0, 2))
            for key, (label, _) in actions.items():
                table.add_row(f"[bold cyan]{key}[/]", label)
            CONSOLE.print(Panel(table, border_style="blue"))
            choice = Prompt.ask("Select", default="4").strip().lower()
            if choice in {"q", "quit", "exit", "0"}:
                self.disconnect()
                return
            if choice not in actions:
                CONSOLE.print("[yellow]Unknown option[/]")
                continue
            label, fn = actions[choice]
            if fn is None:
                continue
            CONSOLE.rule(f"[bold]{label}[/]")
            try:
                fn()
            except ConnectionError as exc:
                CONSOLE.print(f"[red]{exc}[/]")
            except Exception as exc:  # noqa: BLE001 — keep menu alive
                CONSOLE.print(f"[red]Error:[/] {exc}")

    def _banner(self) -> None:
        CONSOLE.print(
            Panel(
                Text.from_markup(
                    "[bold cyan]obdscan[/]  [dim]CLI OBD-II · ELM327 · DoIP manufacturer packs[/]\n"
                    f"[dim]port {self.port} · {len(self.db)} DTC codes · "
                    f"DoIP {'ready' if HAS_DOIP else 'pip install doipclient udsoncan'}[/]"
                ),
                border_style="blue",
            )
        )


# --- argparse / entry -------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="obdscan",
        description="Full-featured CLI OBD-II scanner (interactive menu or subcommands).",
    )
    p.add_argument("-p", "--port", default=DEFAULT_PORT)
    p.add_argument("-b", "--baud", type=int, default=38400)
    p.add_argument("-t", "--timeout", type=float, default=2.0)
    p.add_argument("--dtc-db", default=str(DEFAULT_DTC_DB))

    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("menu", help="Interactive module menu (default)")

    s = sub.add_parser("status", help="Show adapter / ECU status")
    s = sub.add_parser("codes", help="Read DTCs + descriptions")
    s.add_argument("--force", action="store_true")
    s = sub.add_parser("save", help="Save DTCs + vehicle info to Documents/Saved Codes")
    s.add_argument("--force", action="store_true")
    s = sub.add_parser("clear", help="Clear DTCs")
    s.add_argument("--yes", action="store_true")
    s = sub.add_parser("live", help="Stream live data")
    s.add_argument("--once", action="store_true")
    s.add_argument("--graph", action="store_true", help="ASCII live graphs instead of a table")
    s.add_argument(
        "--save",
        metavar="PATH",
        help="On graph stop, write CSV (+ .txt snapshot) to PATH (or under Saved Codes if omitted with prompt)",
    )
    s.add_argument("-i", "--interval", type=float, default=0.4)
    s.add_argument("pids", nargs="*", help="Optional PID names")
    s = sub.add_parser("info", help="Vehicle / adapter info")
    s = sub.add_parser("readiness", help="MIL / monitor readiness")
    s = sub.add_parser("freeze", help="Freeze frame sample")
    s = sub.add_parser("lookup", help="Offline DTC lookup")
    s.add_argument("codes", nargs="+")
    s = sub.add_parser("raw", help="Send raw AT/OBD command")
    s.add_argument("command")
    s = sub.add_parser("pids", help="List built-in + custom live PIDs")
    s = sub.add_parser("scan-pids", help="Scan vehicle Mode 01 support / unlisted PIDs")
    s = sub.add_parser("custom", help="Interactive custom PID menu")

    s = sub.add_parser("manufacturers", help="List manufacturer DoIP/UDS libraries")
    s.add_argument("query", nargs="?", help="Optional search filter")
    s = sub.add_parser("pack", help="Show one manufacturer pack (modules + DIDs)")
    s.add_argument("name", help="Pack id (bmw, vag, mercedes, generic, ...)")

    s = sub.add_parser("doip", help="Enhanced DoIP tools (needs GT327 ethernet + car)")
    dsub = s.add_subparsers(dest="doip_cmd", required=True)
    dsub.add_parser("menu", help="Interactive enhanced DoIP menu")
    dsub.add_parser("discover", help="UDP DoIP vehicle discovery")
    sp = dsub.add_parser("probe", help="Probe manufacturer module LAs on an IP")
    sp.add_argument("-m", "--mfg", default="generic", help="Manufacturer pack id")
    sp.add_argument("--ip", required=True, help="Gateway / ECU IP")
    sp.add_argument("--limit", type=int, default=20, help="Max addresses to probe")
    sr = dsub.add_parser("dids", help="Read pack DIDs from one LA")
    sr.add_argument("-m", "--mfg", default="generic")
    sr.add_argument("--ip", required=True)
    sr.add_argument("--la", required=True, help="Logical address hex, e.g. 1010")
    sd = dsub.add_parser("dtcs", help="Read UDS DTCs from one LA")
    sd.add_argument("-m", "--mfg", default="generic")
    sd.add_argument("--ip", required=True)
    sd.add_argument("--la", required=True)

    return p


def main(argv: list[str] | None = None) -> None:
    # Allow running as script from any cwd
    sys.path.insert(0, str(HERE))
    args = build_parser().parse_args(argv)
    app = App(args.port, args.baud, args.timeout, Path(args.dtc_db))

    cmd = args.cmd or "menu"

    if cmd == "menu":
        app.menu()
        return

    # Offline / DoIP commands — no ELM rfcomm required
    offline = {"lookup", "pids", "manufacturers", "pack", "doip"}
    if cmd not in offline:
        if not app.connect(quiet=False):
            sys.exit(2)

    try:
        if cmd == "status":
            app.show_status()
        elif cmd == "codes":
            app.module_read_codes(force=args.force)
        elif cmd == "save":
            app.module_save_codes(force=args.force)
        elif cmd == "clear":
            app.module_clear_codes(yes=args.yes)
        elif cmd == "live":
            if args.pids:
                app.live_pids = app._parse_live_pid_names(" ".join(args.pids))
            save = Path(args.save) if args.save else None
            # --graph / --save force graphs; otherwise interactive prompt (TTY) or table
            graph: bool | None = True if (args.graph or save) else None
            if not sys.stdin.isatty():
                app._warn_live_pid_count(app.live_pids)
            app.module_live_data(
                once=args.once,
                interval=args.interval,
                graph=graph,
                save_path=save,
            )
        elif cmd == "info":
            app.module_vehicle_info()
        elif cmd == "readiness":
            app.module_readiness()
        elif cmd == "freeze":
            app.module_freeze_frame()
        elif cmd == "lookup":
            app.module_lookup(args.codes)
        elif cmd == "raw":
            app.module_raw(args.command)
        elif cmd == "pids":
            app.module_pid_list()
        elif cmd == "scan-pids":
            app._scan_vehicle_pids()
        elif cmd == "custom":
            app.module_custom_pids()
        elif cmd == "manufacturers":
            if interactive_enhanced_menu is None:
                CONSOLE.print(f"[red]Import error:[/] {_IMPORT_ERR}")
                sys.exit(1)
            show_manufacturer_list(args.query)
        elif cmd == "pack":
            if interactive_enhanced_menu is None:
                CONSOLE.print(f"[red]Import error:[/] {_IMPORT_ERR}")
                sys.exit(1)
            show_pack_detail(get_pack(args.name))
        elif cmd == "doip":
            _run_doip_cli(args)
        else:
            CONSOLE.print(f"[red]Unknown command:[/] {cmd}")
            sys.exit(1)
    finally:
        if cmd not in offline | {"menu"}:
            app.disconnect()


def _run_doip_cli(args: argparse.Namespace) -> None:
    if interactive_enhanced_menu is None:
        CONSOLE.print(f"[red]Import error:[/] {_IMPORT_ERR}")
        sys.exit(1)
    if not HAS_DOIP:
        CONSOLE.print("[red]Install:[/] pip install doipclient udsoncan")
        sys.exit(1)

    sub = args.doip_cmd
    if sub == "menu":
        interactive_enhanced_menu()
        return
    if sub == "discover":
        vehicles = discover_vehicles(timeout=5.0)
        if not vehicles:
            CONSOLE.print("[yellow]No DoIP vehicles discovered.[/]")
            return
        table = Table(title="DoIP discovery")
        table.add_column("IP")
        table.add_column("LA")
        table.add_column("VIN")
        for v in vehicles:
            table.add_row(v.ip, f"{v.logical_address:#06x}", v.vin or "—")
        CONSOLE.print(table)
        return
    if sub == "probe":
        pack = get_pack(args.mfg)
        addrs = pack.all_addresses()[: args.limit]
        results = probe_pack_modules(pack, args.ip, addresses=addrs)
        table = Table(title=f"Probe {pack.id} @ {args.ip}")
        table.add_column("LA")
        table.add_column("Name")
        table.add_column("Status")
        for la, name, status in results:
            table.add_row(f"{la:#06x}", name, status)
        CONSOLE.print(table)
        return
    if sub in {"dids", "dtcs"}:
        pack = get_pack(args.mfg)
        la = int(args.la, 16)
        with DoipSession(
            pack=pack,
            ip=args.ip,
            logical_address=la,
            client_logical_address=pack.tester_address,
            tcp_port=pack.default_doip_port,
        ) as sess:
            CONSOLE.print(sess.change_session(3))
            if sub == "dids":
                rows = read_interesting_dids(sess, pack.dids)
                table = Table(title="DIDs")
                table.add_column("DID")
                table.add_column("Value")
                for k, v in rows:
                    table.add_row(k, v)
                CONSOLE.print(table)
            else:
                ok, result = sess.read_dtcs()
                if not ok:
                    CONSOLE.print(f"[yellow]{result}[/]")
                elif not result:
                    CONSOLE.print("[green]No DTCs[/]")
                else:
                    for c in result:
                        CONSOLE.print(f"  {c}")
        return
    CONSOLE.print(f"[red]Unknown doip subcommand:[/] {sub}")
    sys.exit(1)


if __name__ == "__main__":
    # Ensure local imports work when executed as ./obdscan.py
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
