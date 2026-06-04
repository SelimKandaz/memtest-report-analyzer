
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MemTest Log Analyzer Pro
- System Info is the cover page.
- No "Certified by" text anywhere.
- Optional logo watermark at ~50% opacity, drawn **full-page edge-to-edge** behind content.
- Clean bullets in the header (no &nbsp; artifacts).
- Green accent theme for headings and table headers.
"""

from __future__ import annotations

import os, re, csv, json, sys, tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

# ------------- PDF deps -------------
REPORTLAB_OK = True
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                                    PageBreak)
except Exception:
    REPORTLAB_OK = False

# ------------- PIL (for watermark alpha + trimming) -------------
PIL_OK = True
try:
    from PIL import Image as PILImage, ImageChops
except Exception:
    PIL_OK = False

# ------------- GUI deps -------------
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from xml.sax.saxutils import escape

# ================= Configuration =================
THEME_PRIMARY = (0, 0.6, 0.2)  # green accent
DEFAULT_TOTAL_SLOTS = 24
DEFAULT_LOGO_PATH = "images.png"
DEFAULT_SLOT0_GB = 16.00
APP_TITLE = "MemTest Log Analyzer Pro"

# ================= Data structures =================
@dataclass
class DimmInfo:
    slot_id: Optional[int] = None
    locator: Optional[str] = None
    size_mb: Optional[int] = None
    vendor: Optional[str] = None
    part: Optional[str] = None
    serial: Optional[str] = None
    @property
    def size_gb(self) -> Optional[float]:
        if self.size_mb is None:
            return None
        return self.size_mb / 1024.0
    def display_slot(self) -> str:
        if self.locator and self.locator.strip():
            return self.locator.strip()
        if self.slot_id is not None:
            return f"Slot {self.slot_id}"
        return "Slot ?"

@dataclass
class ParseState:
    start_ts: Optional[datetime] = None
    end_ts: Optional[datetime] = None
    test_date: str = ""
    tool: str = "MemTest"
    version: Optional[str] = None
    aborted: bool = False
    errors_total: int = 0
    planned_passes: Optional[int] = None
    completed_passes: int = 0
    available_gb: Optional[int] = None
    total_bytes: Optional[int] = None
    efi_spec: Optional[str] = None
    system_manu: Optional[str] = None
    system_product: Optional[str] = None
    system_version: Optional[str] = None
    system_sn: Optional[str] = None
    bios_vendor: Optional[str] = None
    bios_version: Optional[str] = None
    bios_date: Optional[str] = None
    cpu: Optional[str] = None
    cpu_clock: Optional[str] = None
    dimms_list: List[DimmInfo] = field(default_factory=list)
    slots_seen: set = field(default_factory=set)
    slots_populated: set = field(default_factory=set)
    tests: List[Dict[str,str]] = field(default_factory=list)
    memtestpro_duration: Optional[str] = None
    @property
    def total_system_gb(self) -> Optional[float]:
        if self.total_bytes:
            return round(self.total_bytes / (1024.0**3), 2)
        return None
    @property
    def total_populated_gb(self) -> Optional[float]:
        vals = [d.size_gb for d in self.dimms_list if d.size_gb]
        if vals:
            return round(sum(vals), 2)
        if self.available_gb is not None:
            return float(self.available_gb)
        return None

# ================= Regex =================
RX = {
    "ts": re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+-\s+(.*)$"),
    "result_line": re.compile(r"Test\s*result\s*:\s*([A-Z ]+)\s*\(Errors\s*:\s*(\d+)\)", re.IGNORECASE),
    "abort": re.compile(r"\bTest aborted\b", re.IGNORECASE),
    "avail_mem_in_ts": re.compile(r"Available\s*Memory:\s*0x[0-9A-Fa-f]+\s*\((\d+)\s*GB\)", re.IGNORECASE),
    "total_mem_mb_in_ts": re.compile(r"Memory\s*:?\s*`?\s*(\d+)\s*MB", re.IGNORECASE),
    "avail_mem": re.compile(r"^Available\s*Memory:\s*0x[0-9A-Fa-f]+\s*\((\d+)\s*GB\)\s*$", re.IGNORECASE),
    "total_mem_bytes": re.compile(r"Total memory size\s*\((\d+)\s*bytes\)", re.IGNORECASE),
    "cpu_line": re.compile(r"CPU\s*:\s*(.*)$", re.IGNORECASE),
    "brand_id": re.compile(r"Brand ID:\s*([^\r\n]+)"),
    "finished_pass": re.compile(r"Finished pass\s*#(\d+)\s*\(of\s*(\d+)\)", re.IGNORECASE),
    "test_exec": re.compile(
        r"Test execution time:\s*([^(]+)\(Test\s*(\d+)\s*cumulative error count:\s*(\d+),\s*buffer full count:\s*(\d+)\)",
        re.IGNORECASE
    ),
    "slot_block": re.compile(r"\[Slot\s*(\d+)\](.*?)(?=\n\[Slot\s*\d+\]|\n\d{4}-\d{2}-\d{2}\s|\Z)", re.IGNORECASE | re.DOTALL),
    "dimm_size": re.compile(r"\bSize\s*:\s*(\d+)(?:\s*MB)?\b", re.IGNORECASE),
    "dimm_vendor": re.compile(r"\b(?:Manufacturer|Vendor)\s*:\s*([^\r\n]+)", re.IGNORECASE),
    "dimm_part": re.compile(r"\b(?:Part\s*Number|PartNumber)\s*:\s*([^\r\n]+)", re.IGNORECASE),
    "dimm_sn": re.compile(r"\b(?:Serial\s*Number|S/N)\s*:\s*([^\r\n]+)", re.IGNORECASE),
    "dimm_locator": re.compile(r"\b(?:Locator|Device Locator|Bank Locator)\s*:\s*([^\r\n]+)", re.IGNORECASE),
    "slot_probe": re.compile(r"\[Slot\s*(\d+)\]", re.IGNORECASE),
    "duration_line": re.compile(r"Duration\s+(\d+)m\s+(\d+)s", re.IGNORECASE),
    "efi_specs": re.compile(r"EFI\s+Specifications:\s*([0-9.]+)", re.IGNORECASE),
    "smbios_bios": re.compile(
        r'SMBIOS BIOS INFO\s+Vendor:\s*"([^"]*)",\s*Version:\s*"([^"]*)",\s*Release Date:\s*"([^"]*)"', re.IGNORECASE),
    "smbios_system": re.compile(
        r'SMBIOS SYSTEM INFO.*?Manufacturer:\s*"([^"]*)",\s*Product:\s*"([^"]*)",\s*Version:\s*"([^"]*)",\s*S/N:\s*"([^"]*)"',
        re.IGNORECASE | re.DOTALL),
    "cpu_speed_mhz": re.compile(r'CPU speed:\s*([\d.]+)\s*MHz', re.IGNORECASE),
    "freq_khz": re.compile(r'Freq:\s*(\d+)KHz', re.IGNORECASE),
}

# ================= Parser =================
def parse_log_text(text: str) -> ParseState:
    s = ParseState()
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        mt = RX["ts"].match(line)
        if mt:
            date_str, time_str, msg = mt.groups()
            try:
                ts = datetime.fromisoformat(f"{date_str} {time_str}")
            except ValueError:
                ts = None
            if ts:
                if s.start_ts is None:
                    s.start_ts, s.test_date = ts, date_str
                s.end_ts = ts
            m = RX["avail_mem_in_ts"].search(msg)
            if m:
                try: s.available_gb = int(m.group(1))
                except: pass
            m = RX["total_mem_mb_in_ts"].search(msg)
            if m:
                try: s.total_bytes = int(m.group(1)) * 1024 * 1024
                except: pass
            m = RX["cpu_line"].search(msg)
            if m: s.cpu = m.group(1).strip()
            m = RX["result_line"].search(msg)
            if m:
                try: s.errors_total = int(m.group(2))
                except: pass
            if RX["abort"].search(msg):
                s.aborted = True
            m = RX["finished_pass"].search(msg)
            if m:
                try:
                    s.completed_passes = max(s.completed_passes, int(m.group(1)))
                    s.planned_passes = int(m.group(2))
                except: pass
            m = RX["test_exec"].search(msg)
            if m:
                time_str2, tid, errs, buf = m.groups()
                s.tests.append({"id": tid, "time": time_str2.strip(), "errors": errs, "buf": buf})
            m = RX["duration_line"].search(msg)
            if m:
                mins = int(m.group(1)); secs = int(m.group(2))
                s.memtestpro_duration = f"{mins}m {secs}s"
            m = RX["slot_probe"].search(msg)
            if m:
                try: s.slots_seen.add(int(m.group(1)))
                except: pass
        else:
            m = RX["avail_mem"].search(line)
            if m:
                try: s.available_gb = int(m.group(1))
                except: pass
            m = RX["total_mem_bytes"].search(line)
            if m:
                try: s.total_bytes = int(m.group(1))
                except: pass
            m = RX["slot_probe"].search(line)
            if m:
                try: s.slots_seen.add(int(m.group(1)))
                except: pass

    for blk in RX["slot_block"].finditer(text):
        sid = int(blk.group(1)); body = blk.group(2)
        di = DimmInfo(slot_id=sid)
        m = RX["dimm_locator"].search(body);   di.locator = (m.group(1).strip() if m else None)
        m = RX["dimm_size"].search(body);      di.size_mb = (int(m.group(1)) if m else None)
        m = RX["dimm_vendor"].search(body);    di.vendor = (m.group(1).strip() if m else None)
        m = RX["dimm_part"].search(body);      di.part = (m.group(1).strip() if m else None)
        m = RX["dimm_sn"].search(body);        di.serial = (m.group(1).strip() if m else None)
        if any([di.locator, di.size_mb, di.vendor, di.part, di.serial]):
            s.dimms_list.append(di)
            if di.size_mb and di.size_mb > 0: s.slots_populated.add(sid)
            s.slots_seen.add(sid)

    m = RX["efi_specs"].search(text)
    if m: s.efi_spec = m.group(1)
    m = RX["smbios_bios"].search(text)
    if m: s.bios_vendor, s.bios_version, s.bios_date = m.groups()
    m = RX["smbios_system"].search(text)
    if m: s.system_manu, s.system_product, s.system_version, s.system_sn = m.groups()
    if not s.cpu:
        m = RX["brand_id"].search(text)
        if m: s.cpu = m.group(1).strip()
    m = RX["cpu_speed_mhz"].search(text)
    if m:
        s.cpu_clock = f"{m.group(1)} MHz"
    else:
        m = RX["freq_khz"].search(text)
        if m:
            try:
                s.cpu_clock = f"{int(m.group(1))/1000.0:.1f} MHz"
            except Exception:
                pass
    return s

# ================= Helpers =================
def _fmt_gb(x: Optional[float]) -> str:
    return "" if x is None else f"{x:.2f} GB"

def _duration_text(s: ParseState) -> str:
    if s.memtestpro_duration:
        m = re.match(r"^\\s*(\\d+)m\\s+(\\d+)s\\s*$", s.memtestpro_duration)
        if m:
            minutes = int(m.group(1)); seconds = int(m.group(2))
            if minutes >= 100:
                hours = minutes // 60; rem = minutes % 60
                return f"{hours}h {rem}m {seconds}s"
            return f"{minutes}m {seconds}s"
    if s.start_ts and s.end_ts:
        total = int((s.end_ts - s.start_ts).total_seconds())
        minutes = total // 60; seconds = total % 60
        if minutes >= 100:
            hours = minutes // 60; rem = minutes % 60
            return f"{hours}h {rem}m {seconds}s"
        return f"{minutes}m {seconds}s"
    return ""

def _result_text(s: ParseState) -> str:
    if s.errors_total == 0 and not s.aborted: return "PASS"
    if s.errors_total == 0 and s.aborted: return "INCOMPLETE"
    if s.errors_total > 0: return "FAIL"
    return "Unknown"

def _mk_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("Small", fontSize=9, leading=11))
    styles.add(ParagraphStyle("Center", parent=styles["Normal"], alignment=1))
    styles.add(ParagraphStyle("H1", parent=styles["Heading1"], fontSize=18, leading=22, spaceAfter=10))
    styles.add(ParagraphStyle("H0", parent=styles["Heading1"], fontSize=22, leading=26, spaceAfter=12, alignment=1, textColor=colors.Color(*THEME_PRIMARY)))
    styles.add(ParagraphStyle("Section", parent=styles["Heading2"], fontSize=14, spaceBefore=6, spaceAfter=6, textColor=colors.Color(*THEME_PRIMARY)))
    styles.add(ParagraphStyle("Muted", parent=styles["Normal"], textColor=colors.grey, fontSize=9))
    return styles

def _P(txt, style): return Paragraph(escape(str(txt or "")), style)

# ---- Watermark helpers ----
def _trim_white_borders(img: PILImage.Image) -> PILImage.Image:
    """Trim white-ish borders from an RGBA or RGB image (no numpy)."""
    try:
        if img.mode != "RGBA":
            base = img.convert("RGBA")
        else:
            base = img.copy()

        # If alpha already present: use alpha bbox first
        alpha = base.split()[3]
        bbox = alpha.getbbox()
        if bbox: base = base.crop(bbox)

        # Also trim by comparing to white background (helps with solid white padding)
        bg = PILImage.new("RGBA", base.size, (255, 255, 255, 255))
        diff = ImageChops.difference(base, bg)
        # Boost difference to make near-white visible
        diff = ImageChops.add(diff, diff, 2.0, 0)
        bbox2 = diff.getbbox()
        if bbox2: base = base.crop(bbox2)

        return base
    except Exception:
        return img

def _prep_logo_translucent(src_path: str, alpha_0_1: float) -> Optional[str]:
    """Return a semi-transparent, trimmed PNG path for the watermark."""
    if not os.path.isfile(src_path): return None
    if not PIL_OK: return src_path
    try:
        img = PILImage.open(src_path)
        img = _trim_white_borders(img)
        # ensure RGBA
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        # apply global alpha
        a = img.split()[3]
        target = max(0, min(1, alpha_0_1))
        # Build a constant alpha layer and multiply
        alpha_layer = PILImage.new("L", img.size, int(target * 255))
        img.putalpha(alpha_layer)

        fd, tmp = tempfile.mkstemp(prefix="logo_fullpage_", suffix=".png")
        os.close(fd)
        img.save(tmp, "PNG")
        return tmp
    except Exception:
        return src_path

def _draw_page_frame(canvas, doc, title: str):
    # header
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.grey)
    canvas.drawString(36, doc.height + doc.topMargin + 6, title)
    canvas.restoreState()
    # footer
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.setFillColor(colors.grey)
    canvas.drawRightString(doc.width + doc.leftMargin, 20, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()

def _draw_watermark(canvas, doc, logo_path: Optional[str], alpha: float = 0.5):
    if not logo_path or not os.path.isfile(logo_path): return
    canvas.saveState()
    try:
        page_w, page_h = doc.pagesize
        if hasattr(canvas, "setFillAlpha"):
            canvas.setFillAlpha(alpha)
            canvas.setStrokeAlpha(alpha)
        # Full-bleed stretch, no aspect ratio lock
        canvas.drawImage(logo_path, 0, 0, width=page_w, height=page_h, mask='auto', preserveAspectRatio=False)
    finally:
        canvas.restoreState()

# ================= GUI =================
class App(ttk.Frame):
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        master.title(APP_TITLE)
        master.geometry("1200x780"); master.minsize(900, 600)

        style = ttk.Style()
        try: style.theme_use("clam")
        except: pass

        self.state_data: Optional[ParseState] = None
        self.logo_var = tk.StringVar(value=DEFAULT_LOGO_PATH)
        self.total_slots_var = tk.IntVar(value=DEFAULT_TOTAL_SLOTS)
        self.watermark_var = tk.BooleanVar(value=True)

        menubar = tk.Menu(master)
        filem = tk.Menu(menubar, tearoff=0)
        filem.add_command(label="Open Log…", command=self.open_file)
        filem.add_separator()
        filem.add_command(label="Export CSV…", command=self.export_csv)
        filem.add_command(label="Export JSON…", command=self.export_json)
        filem.add_command(label="Export PDF…", command=self.export_pdf)
        filem.add_separator()
        filem.add_command(label="Exit", command=master.destroy)
        menubar.add_cascade(label="File", menu=filem)
        master.config(menu=menubar)

        top = ttk.Frame(self); top.pack(fill="x", pady=6, padx=8)
        ttk.Button(top, text="Open Log", command=self.open_file).pack(side="left", padx=(0,6))
        ttk.Button(top, text="Analyze", command=self.analyze).pack(side="left", padx=6)
        ttk.Button(top, text="Export CSV", command=self.export_csv).pack(side="left", padx=6)
        ttk.Button(top, text="Export JSON", command=self.export_json).pack(side="left", padx=6)
        ttk.Button(top, text="Export PDF", command=self.export_pdf).pack(side="left", padx=6)

        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Label(top, text="Logo:").pack(side="left")
        ttk.Entry(top, textvariable=self.logo_var, width=42).pack(side="left", padx=4)
        ttk.Button(top, text="Browse", command=self.pick_logo).pack(side="left", padx=(0,10))
        ttk.Checkbutton(top, text="Watermark logo full-page (50% alpha)", variable=self.watermark_var).pack(side="left", padx=(0,12))

        ttk.Label(top, text="Total Slots:").pack(side="left")
        ttk.Spinbox(top, from_=1, to=64, textvariable=self.total_slots_var, width=4).pack(side="left")

        paned = ttk.Panedwindow(self, orient="vertical")
        paned.pack(fill="both", expand=True, padx=8, pady=(0,6))
        log_frame = ttk.Labelframe(paned, text="Log")
        self.log_input = scrolledtext.ScrolledText(log_frame, height=16, wrap="none")
        self.log_input.pack(fill="both", expand=True, padx=6, pady=6)
        paned.add(log_frame, weight=3)
        sum_frame = ttk.Labelframe(paned, text="Summary")
        self.summary = scrolledtext.ScrolledText(sum_frame, height=12, wrap="word")
        self.summary.pack(fill="both", expand=True, padx=6, pady=6)
        paned.add(sum_frame, weight=2)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", side="bottom", padx=8, pady=(0,8))
        self.pack(fill="both", expand=True)

    def pick_logo(self):
        p = filedialog.askopenfilename(title="Choose Logo",
            filetypes=[("Image files","*.png *.jpg *.jpeg *.bmp *.gif"), ("All files","*.*")])
        if p: self.logo_var.set(p)

    def open_file(self):
        p = filedialog.askopenfilename(title="Open MemTest Log",
            filetypes=[("Log files","*.log *.txt"), ("All files","*.*")])
        if not p: return
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
            self.log_input.delete("1.0", tk.END); self.log_input.insert(tk.END, txt)
            self.status.set(f"Loaded: {os.path.basename(p)}")
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def analyze(self):
        txt = self.log_input.get("1.0", tk.END)
        if not txt.strip():
            messagebox.showwarning("No data", "Paste or open a log first."); return
        self.state_data = parse_log_text(txt); s = self.state_data
        total_slots = self.total_slots_var.get() or DEFAULT_TOTAL_SLOTS
        populated = len(s.slots_populated)
        out = []
        out.append("=== Summary ===")
        out.append(f"Date: {s.test_date}")
        out.append(f"Duration: {_duration_text(s)}")
        out.append(f"Result: {_result_text(s)}")
        out.append(f"Modules populated: {populated}/{total_slots}")
        if s.total_populated_gb is not None: out.append(f"Total Populated (by DIMMs): {_fmt_gb(s.total_populated_gb)}")
        if s.available_gb is not None: out.append(f"Available Memory (log): {s.available_gb} GB")
        if s.planned_passes: out.append(f"Passes: {s.completed_passes}/{s.planned_passes}")
        if s.cpu: out.append(f"CPU: {s.cpu}")
        if s.tests:
            out.append("\\n=== Per-Test Results ===")
            for trow in s.tests:
                out.append(f"Test {trow['id']}: time={trow['time']}  errors={trow['errors']}  buffer_full={trow['buf']}")
        out.append("\\n=== System Information ===")
        out.append(f"EFI Specifications: {s.efi_spec or ''}")
        out.append(f"System Manufacturer: {s.system_manu or ''}")
        out.append(f"Product Name: {s.system_product or ''}")
        out.append(f"Version: {s.system_version or ''}")
        out.append(f"Serial Number: {s.system_sn or ''}")
        out.append(f"BIOS Vendor: {s.bios_vendor or ''}")
        out.append(f"BIOS Version: {s.bios_version or ''}")
        out.append(f"BIOS Release Date: {s.bios_date or ''}")
        out.append(f"CPU Type: {s.cpu or ''}")
        out.append(f"CPU Clock: {s.cpu_clock or ''}")
        if s.available_gb is not None: out.append(f"Memory (Available): {s.available_gb} GB")
        self.summary.delete("1.0", tk.END); self.summary.insert(tk.END, "\\n".join(out))
        self.status.set("Analysis complete.")

    # --------- Exports ---------
    def export_csv(self):
        if not self._ensure_analyzed(): return
        p = filedialog.asksaveasfilename(defaultextension=".csv", title="Save CSV")
        if not p: return
        s = self.state_data; total_slots = self.total_slots_var.get() or DEFAULT_TOTAL_SLOTS
        populated = len(s.slots_populated)
        try:
            with open(p, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Field","Value"])
                w.writerow(["Date", s.test_date])
                w.writerow(["Duration", _duration_text(s)])
                w.writerow(["Result", _result_text(s)])
                w.writerow(["Modules populated", f"{populated}/{total_slots}"])
                w.writerow(["Total Populated (by DIMMs)", _fmt_gb(s.total_populated_gb) if s.total_populated_gb is not None else ""])
                w.writerow(["Available Memory (log)", f"{s.available_gb} GB" if s.available_gb is not None else ""])
                w.writerow(["Passes", f"{s.completed_passes}/{s.planned_passes}" if s.planned_passes else ""])
                if s.tests:
                    w.writerow([]); w.writerow(["Per-Test Results"]); w.writerow(["Test #","Execution Time","Errors","Buffer Full"])
                    for trow in s.tests:
                        w.writerow([trow["id"], trow["time"], trow["errors"], trow["buf"]])
                w.writerow([]); w.writerow(["System Information"])
                w.writerow(["EFI Specifications", s.efi_spec or ""])
                w.writerow(["System Manufacturer", s.system_manu or ""])
                w.writerow(["Product Name", s.system_product or ""])
                w.writerow(["Version", s.system_version or ""])
                w.writerow(["Serial Number", s.system_sn or ""])
                w.writerow(["BIOS Vendor", s.bios_vendor or ""])
                w.writerow(["BIOS Version", s.bios_version or ""])
                w.writerow(["BIOS Release Date", s.bios_date or ""])
                w.writerow(["CPU Type", s.cpu or ""])
                w.writerow(["CPU Clock", s.cpu_clock or ""])
                w.writerow(["Memory", f"{s.available_gb} GB" if s.available_gb is not None else ""])
            messagebox.showinfo("Export", "CSV exported.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def export_json(self):
        if not self._ensure_analyzed(): return
        p = filedialog.asksaveasfilename(defaultextension=".json", title="Save JSON")
        if not p: return
        s = self.state_data; total_slots = self.total_slots_var.get() or DEFAULT_TOTAL_SLOTS
        payload = {
            "date": s.test_date,
            "duration": _duration_text(s),
            "result": _result_text(s),
            "modules_populated": f"{len(s.slots_populated)}/{total_slots}",
            "total_populated_gb": s.total_populated_gb,
            "available_memory_log_gb": s.available_gb,
            "passes": f"{s.completed_passes}/{s.planned_passes}" if s.planned_passes else None,
            "cpu": s.cpu,
            "tests": s.tests,
            "system_information": {
                "efi_specifications": s.efi_spec,
                "system_manufacturer": s.system_manu,
                "product_name": s.system_product,
                "version": s.system_version,
                "serial_number": s.system_sn,
                "bios_vendor": s.bios_vendor,
                "bios_version": s.bios_version,
                "bios_release_date": s.bios_date,
                "cpu_type": s.cpu,
                "cpu_clock": s.cpu_clock,
                "memory_available_log_gb": s.available_gb,
            }
        }
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            messagebox.showinfo("Export", "JSON exported.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def export_pdf(self):
        if not self._ensure_analyzed(): return
        if not REPORTLAB_OK:
            messagebox.showerror("Missing", "Install reportlab: pip install reportlab"); return
        pth = filedialog.asksaveasfilename(defaultextension=".pdf", title="Save PDF")
        if not pth: return
        s = self.state_data
        total_slots = self.total_slots_var.get() or DEFAULT_TOTAL_SLOTS
        populated = len(s.slots_populated)

        styles = _mk_styles()
        story = []

        # ----- Cover -----
        story.append(Paragraph("MemTest Report", styles["H0"]))
        when = s.test_date or ""
        result = _result_text(s)
        duration = _duration_text(s)
        # Clean bullets, no &nbsp;
        story.append(Paragraph(f"Date: {when}  •  Result: <b>{result}</b>  •  Duration: {duration}", styles["Center"]))
        story.append(Spacer(1, 0.18*inch))

        # Accent rule
        from reportlab.graphics.shapes import Drawing, Line
        d = Drawing(500, 2); ln = Line(0, 1, 500, 1)
        ln.strokeColor = colors.Color(*THEME_PRIMARY); ln.strokeWidth = 2; d.add(ln)
        story.append(d); story.append(Spacer(1, 0.18*inch))

        sys_rows = [
            ["Field","Value"],
            ["EFI Specifications", s.efi_spec or ""],
            ["System Manufacturer", s.system_manu or ""],
            ["Product Name", s.system_product or ""],
            ["Version", s.system_version or ""],
            ["Serial Number", s.system_sn or ""],
            ["BIOS Vendor", s.bios_vendor or ""],
            ["BIOS Version", s.bios_version or ""],
            ["BIOS Release Date", s.bios_date or ""],
            ["CPU Type", s.cpu or ""],
            ["CPU Clock", s.cpu_clock or ""],
            ["Memory (Available from log)", f"{s.available_gb} GB" if s.available_gb is not None else ""],
        ]
        t_sys = Table(sys_rows, colWidths=[2.7*inch, 4.1*inch], repeatRows=1, hAlign='LEFT')
        t_sys.setStyle(TableStyle([
            ("GRID",(0,0),(-1,-1),0.3,colors.black),
            ("BACKGROUND",(0,0),(-1,0),colors.Color(*THEME_PRIMARY)),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.Color(0.97,0.97,0.97)]),
            ("FONT",(0,0),(-1,-1),"Helvetica",9),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        story.append(t_sys)
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("Generated by MemTest Log Analyzer (Pro).", styles["Muted"]))
        story.append(PageBreak())

        # ----- Summary / Results -----
        story.append(Paragraph("<b>Summary</b>", styles["Section"]))
        rows = [
            ["Field", "Value"],
            ["Date", s.test_date],
            ["Duration", duration],
            ["Result", result],
            ["Modules populated", f"{populated}/{total_slots}"],
            ["Total Populated (by DIMMs)", _fmt_gb(s.total_populated_gb) if s.total_populated_gb is not None else ""],
            ["Available Memory (log)", f"{s.available_gb} GB" if s.available_gb is not None else ""],
            ["Passes", f"{s.completed_passes}/{s.planned_passes}" if s.planned_passes else ""],
        ]
        t = Table(rows, colWidths=[2.7*inch, 4.1*inch], repeatRows=1)
        t.setStyle(TableStyle([
            ("GRID",(0,0),(-1,-1),0.3,colors.black),
            ("BACKGROUND",(0,0),(-1,0),colors.Color(*THEME_PRIMARY)),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.Color(0.97,0.97,0.97)]),
            ("FONT",(0,0),(-1,-1),"Helvetica",9),
        ]))
        story.append(t); story.append(Spacer(1, 0.18*inch))

        if s.tests:
            story.append(Paragraph("<b>Per-Test Results</b>", styles["Section"]))
            rows = [["Test #","Execution Time","Errors","Buffer Full"]]
            for r in s.tests: rows.append([r["id"], r["time"], r["errors"], r["buf"]])
            t2 = Table(rows, colWidths=[1.0*inch, 3.0*inch, 1.2*inch, 1.3*inch], repeatRows=1)
            t2.setStyle(TableStyle([
                ("GRID",(0,0),(-1,-1),0.3,colors.black),
                ("BACKGROUND",(0,0),(-1,0),colors.Color(*THEME_PRIMARY)),
                ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                ("FONT",(0,0),(-1,-1),"Helvetica",9),
            ]))
            story.append(t2); story.append(Spacer(1, 0.18*inch))

        # Memory table
        slot0_gb = DEFAULT_SLOT0_GB
        for dmm in s.dimms_list:
            if (dmm.slot_id == 0 or (dmm.locator and dmm.locator.strip().lower() == "slot 0")) and dmm.size_gb:
                slot0_gb = round(float(dmm.size_gb), 2); break
        story.append(Paragraph("<b>Memory</b>", styles["Section"]))
        mem_rows = [["Slot", "Size"]]
        total_slots = self.total_slots_var.get() or DEFAULT_TOTAL_SLOTS
        for i in range(total_slots): mem_rows.append([f"Slot {i}", f"{slot0_gb:.2f} GB"])
        t3 = Table(mem_rows, colWidths=[1.2*inch, 1.2*inch], repeatRows=1)
        t3.setStyle(TableStyle([
            ("GRID",(0,0),(-1,-1),0.3,colors.black),
            ("BACKGROUND",(0,0),(-1,0),colors.Color(*THEME_PRIMARY)),
            ("TEXTCOLOR",(0,0),(-1,0),colors.white),
            ("ALIGN",(1,1),(1,-1),"RIGHT"),
            ("FONT",(0,0),(-1,-1),"Helvetica",9),
        ]))
        story.append(t3)

        # Prepare watermark asset
        logo_path = (self.logo_var.get() or "").strip()
        translucent_logo = None
        if self.watermark_var.get() and logo_path and os.path.isfile(logo_path):
            translucent_logo = _prep_logo_translucent(logo_path, 0.5)

        class NumberedDoc(SimpleDocTemplate): pass
        doc = NumberedDoc(pth, pagesize=LETTER, leftMargin=36, rightMargin=36, topMargin=48, bottomMargin=36)

        def on_page(canv, doc_ref):
            # Draw watermark FIRST (behind everything), full-bleed
            if translucent_logo:
                _draw_watermark(canv, doc, translucent_logo, alpha=0.5)
            # Header/footer last
            _draw_page_frame(canv, doc, "MemTest Report")

        try:
            doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
            messagebox.showinfo("Export", "PDF exported.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def _ensure_analyzed(self) -> bool:
        if not self.state_data:
            messagebox.showwarning("No data", "Run Analyze first."); return False
        return True

def main():
    root = tk.Tk(); App(root); root.mainloop()

if __name__ == "__main__":
    main()
