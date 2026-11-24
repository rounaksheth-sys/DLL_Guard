"""
DLLGuard

Looks at the DLLs loaded by running programs, checks where they live and who
signed them, then gives each file a score.

A HIGH or MEDIUM score only means the file matches my rules. It is not proof
that the file is malware. A lot of normal apps keep unsigned or third-party
DLLs in folders the user can write to (AppData, ProgramData, and so on).

How to run:
    py dllguard.py                  every running process
    py dllguard.py notepad.exe      every copy of one program
    py dllguard.py 11852            one process, by PID
    py dllguard.py --help

Needs:  py -m pip install psutil colorama
Run it from a normal PowerShell window. Administrator sees more processes.
"""
import csv
import ctypes
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import psutil
from colorama import init, Fore, Style

# Windows itself. A normal user cannot drop a DLL here.
SYSTEM = (r"c:\windows\system32", r"c:\windows\syswow64", r"c:\windows\winsxs",
          r"c:\windows\assembly")
# Installed programs. Also protected, so "not in System32" is not enough to flag.
PROTECTED = (r"c:\program files\windowsapps", r"c:\program files",
             r"c:\program files (x86)")
# Places a user (or a dropped file) can write to.
USER_WRITABLE = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\",
                 "\\programdata\\", "\\users\\public\\")

# 2 points is MEDIUM. That is the lowest score I treat as flagged.
FLAG_MIN_SCORE = 2

# One PowerShell window per DLL was too slow, so I check 50 files at a time.
SIG_BATCH_SIZE = 50

CSV_FIELDS = ["module", "location", "flagged", "score", "risk", "signature",
              "signer", "reasons", "seen_in_processes", "processes"]

USAGE = """Usage:
  py dllguard.py                   scan every running process
  py dllguard.py <program name>    scan one program, e.g. py dllguard.py notepad.exe
  py dllguard.py <PID number>      scan one process, e.g. py dllguard.py 11852"""

sig_cache = {}     # already-checked path -> status and signer
stats = {"skipped": 0}


def classify(path):
    # user-writable is checked before Program Files on purpose:
    # a path like ProgramData is writable even if the name looks official
    if path.startswith(SYSTEM):
        return "system"
    if any(x in path for x in USER_WRITABLE):
        return "user-writable"
    if path.startswith(PROTECTED):
        return "protected"
    return "other"


def in_app_folder(path, exe_dir):
    # exe_dir already ends with a backslash, so "C:\\app" does not match "C:\\app2"
    return path.startswith(exe_dir)


def read_signature_json(out):
    text = (out or "").strip()
    if not text:
        return []
    data = json.loads(text)
    # one file comes back as a dict, several files come back as a list
    if isinstance(data, dict):
        return [data]
    return data


def check_signatures_batch(paths):
    # Get-AuthenticodeSignature is still slow. The win is starting PowerShell
    # once for the whole batch instead of once per file.
    # Paths go in a temp file because a long command line gets cut off.
    if not paths:
        return {}

    handle, list_path = tempfile.mkstemp(prefix="dllguard_", suffix=".txt", text=True)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            for p in paths:
                f.write(p + "\n")

        # the path list is read with LiteralPath, so a quote in a DLL path is safe
        script = (
            "$list = Get-Content -LiteralPath '"
            + list_path.replace("'", "''")
            + "' -Encoding UTF8; "
            "$rows = foreach ($p in $list) { "
            "  if (-not $p) { continue }; "
            "  try { "
            "    $s = Get-AuthenticodeSignature -LiteralPath $p; "
            "    $signer = $null; "
            "    if ($s.SignerCertificate) { $signer = $s.SignerCertificate.Subject }; "
            "    [pscustomobject]@{Path=$p; Status=$s.Status.ToString(); Signer=$signer} "
            "  } catch { "
            "    [pscustomobject]@{Path=$p; Status='Error'; Signer=$null} "
            "  } "
            "}; "
            "if ($rows) { $rows | ConvertTo-Json -Compress }"
        )
        cmd = ["powershell", "-NoProfile", "-NoLogo", "-Command", script]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        rows = read_signature_json(proc.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return {p: {"Status": "Error", "Signer": None} for p in paths}
    finally:
        try:
            os.remove(list_path)
        except OSError:
            pass

    found = {}
    for row in rows:
        path = (row.get("Path") or "").lower()
        if path:
            found[path] = {"Status": row.get("Status") or "Error",
                           "Signer": row.get("Signer")}
    for p in paths:
        if p not in found:
            found[p] = {"Status": "Error", "Signer": None}
    return found


def prefetch_signatures(paths):
    unknown = []
    seen = set()
    for path in paths:
        if not path or path in sig_cache or path in seen:
            continue
        seen.add(path)
        unknown.append(path)
    if not unknown:
        return

    print(f"Checking signatures of {len(unknown)} file(s), "
          f"{SIG_BATCH_SIZE} at a time...", flush=True)
    for i in range(0, len(unknown), SIG_BATCH_SIZE):
        chunk = unknown[i:i + SIG_BATCH_SIZE]
        done = i + len(chunk)
        print(f"  {done} of {len(unknown)}", flush=True)
        sig_cache.update(check_signatures_batch(chunk))


def cached_signature(path):
    if path not in sig_cache:
        prefetch_signatures([path])
    return sig_cache[path]


def get_cn(subject):
    # certificate subject looks like "CN=Microsoft Corporation, O=..."
    if not subject:
        return "none"
    m = re.search(r'CN=(?:"([^"]+)"|([^,]+))', subject)
    if m:
        return m.group(1) or m.group(2)
    return subject


def normalize(cn):
    # "Microsoft Windows" and "Microsoft Corporation" are the same publisher
    # for this project. Other companies with more than one certificate name
    # can still look different. That is a known limit.
    cn = cn.lower()
    if cn.startswith("microsoft"):
        return "microsoft"
    return cn


def score(path, exe_dir, exe_signer, sig):
    # weights are my own choices, not a published formula
    # writable folder +1, outside the program's folder +1,
    # bad/missing signature +3, different signer +1
    pts, reasons = 0, []
    if any(x in path for x in USER_WRITABLE):
        pts += 1
        reasons.append("user-writable location")
    if not in_app_folder(path, exe_dir):
        pts += 1
        reasons.append("outside app folder")
    if sig["Status"] != "Valid":
        pts += 3
        reasons.append(f"signature {sig['Status']}")
    elif normalize(get_cn(sig["Signer"])) != normalize(exe_signer):
        pts += 1
        reasons.append("signer differs from process publisher")
    return pts, reasons


def score_trusted(sig):
    # System32 / Program Files: location is fine, so only a bad signature counts
    if sig["Status"] != "Valid":
        return 3, [f"signature {sig['Status']}"]
    return 0, []


def risk_label(pts):
    if pts >= 4:
        return "HIGH"
    if pts >= 2:
        return "MEDIUM"
    if pts >= 1:
        return "LOW"
    return "OK"


def make_row(pname, pid, path, tier, pts, reasons, sig):
    return {
        "process": pname, "pid": pid, "module": path, "location": tier,
        "flagged": "yes" if pts >= FLAG_MIN_SCORE else "no",
        "score": pts, "risk": risk_label(pts),
        "signature": sig["Status"], "signer": get_cn(sig["Signer"]),
        "reasons": "; ".join(reasons),
    }


def find_pids(target):
    pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        name = proc.info['name']
        if name and name.lower() == target.lower():
            pids.append(proc.info['pid'])
    return pids


def collect_pid(pid):
    # just the file list here. signatures happen after, in one batch
    start = time.time()
    dlls = set()
    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
        pname = proc.name()
        for m in proc.memory_maps():
            path = m.path.lower()
            # memory_maps also returns fonts, .mui, etc. I only want code modules
            if path.endswith((".dll", ".drv")):
                dlls.add(path)
    except psutil.Error:
        # lsass and similar are protected; some processes close while we scan
        stats["skipped"] += 1
        return None
    if not exe:
        stats["skipped"] += 1
        return None

    print(f"PID {pid} ({pname}): {len(dlls)} modules "
          f"({time.time() - start:.1f}s)", flush=True)

    return {
        "pid": pid, "name": pname, "exe": exe,
        "exe_dir": os.path.dirname(exe).lower().rstrip("\\") + "\\",
        "dlls": dlls, "rows": None,
        "trusted": None, "trusted_rows": None,
    }


def score_process(p):
    exe_dir = p["exe_dir"]
    exe_signer = get_cn(cached_signature(p["exe"].lower())["Signer"])
    p["publisher"] = exe_signer

    rows = []
    trusted = []
    for d in sorted(p["dlls"]):
        tier = classify(d)
        # skip System32 and Program Files unless the user asks to include them
        if tier in ("system", "protected"):
            trusted.append((tier, d))
            continue
        sig = cached_signature(d)
        pts, reasons = score(d, exe_dir, exe_signer, sig)
        rows.append(make_row(p["name"], p["pid"], d, tier, pts, reasons, sig))

    p["rows"] = rows
    p["trusted"] = trusted
    p["total"] = len(p["dlls"])
    n_flagged = sum(1 for r in rows if r["score"] >= FLAG_MIN_SCORE)
    print(f"PID {p['pid']} ({p['name']}): {p['total']} modules, "
          f"{n_flagged} flagged", flush=True)


def score_collected(procs):
    paths = []
    for p in procs:
        paths.append(p["exe"].lower())
        for d in p["dlls"]:
            if classify(d) not in ("system", "protected"):
                paths.append(d)
    prefetch_signatures(paths)
    print("Scoring...", flush=True)
    for p in procs:
        score_process(p)


def ensure_verified(p):
    if p["trusted_rows"] is not None:
        return
    rows = []
    for tier, d in p["trusted"]:
        sig = cached_signature(d)
        pts, reasons = score_trusted(sig)
        rows.append(make_row(p["name"], p["pid"], d, tier, pts, reasons, sig))
    p["trusted_rows"] = rows


def get_rows(procs, include_windows):
    if include_windows:
        todo = []
        for p in procs:
            if p["trusted_rows"] is None:
                todo.extend(d for _, d in p["trusted"])
        if todo:
            prefetch_signatures(todo)
    rows = []
    for p in procs:
        rows.extend(p["rows"])
        if include_windows:
            ensure_verified(p)
            rows.extend(p["trusted_rows"])
    return rows


def group_by_file(rows):
    # Nahimic shows up in lots of processes. Report the file once.
    groups = {}
    for r in rows:
        g = groups.get(r["module"])
        if g is None:
            groups[r["module"]] = {"best": r, "pids": {r["pid"]}, "names": {r["process"]}}
        else:
            g["pids"].add(r["pid"])
            g["names"].add(r["process"])
            if r["score"] > g["best"]["score"]:
                g["best"] = r
    out = []
    for g in groups.values():
        row = dict(g["best"])
        row["seen_in_processes"] = len(g["pids"])
        row["processes"] = "; ".join(sorted(g["names"]))
        out.append(row)
    return out


def one_per_process(rows):
    out = []
    for r in rows:
        row = dict(r)
        row["seen_in_processes"] = 1
        row["processes"] = f"{r['process']} (PID {r['pid']})"
        out.append(row)
    return out


USE_COLOR = sys.stdout.isatty()
init()

COLORS = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW,
          "LOW": Fore.GREEN, "OK": Fore.LIGHTBLACK_EX}


def paint(text, risk):
    if not USE_COLOR:
        return text
    return f"{COLORS.get(risk, '')}{text}{Style.RESET_ALL}"


# what the menu is showing right now
RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "OK": 3}
view = {"levels": {"HIGH", "MEDIUM"}, "high_first": True, "group": True}

LEVEL_CHOICES = {
    "1": ({"HIGH", "MEDIUM"}, "HIGH and MEDIUM (flagged)"),
    "2": ({"HIGH"}, "HIGH only"),
    "3": ({"HIGH", "MEDIUM", "LOW", "OK"}, "all levels"),
    "4": ({"LOW", "OK"}, "LOW and OK only"),
}


def view_text():
    names = [n for n in ("HIGH", "MEDIUM", "LOW", "OK") if n in view["levels"]]
    order = "highest first" if view["high_first"] else "lowest first"
    group = "one line per file" if view["group"] else "one line per process"
    return f"{', '.join(names)}; {order}; {group}"


def apply_view(rows):
    rows = group_by_file(rows) if view["group"] else one_per_process(rows)
    rows = [r for r in rows if r["risk"] in view["levels"]]
    if view["high_first"]:
        rows.sort(key=lambda r: (RANK[r["risk"]], -r["score"], r["module"]))
    else:
        rows.sort(key=lambda r: (-RANK[r["risk"]], r["score"], r["module"]))
    return rows


def change_view():
    print("\nWhich levels do you want to see?")
    for k, (_, label) in LEVEL_CHOICES.items():
        print(f"  {k}  {label}")
    c = input("Choose 1-4 (press Enter to keep this): ").strip()
    if c in LEVEL_CHOICES:
        view["levels"] = set(LEVEL_CHOICES[c][0])
    elif c:
        print("That was not 1-4, so I left the levels as they were.")

    print("\nWhich order?")
    print("  1  Highest risk first")
    print("  2  Lowest risk first")
    o = input("Choose 1-2 (press Enter to keep this): ").strip()
    if o == "1":
        view["high_first"] = True
    elif o == "2":
        view["high_first"] = False
    elif o:
        print("That was not 1 or 2, so I left the order as it was.")

    print("\nSame file loaded by several programs:")
    print("  1  Show it once, and say how many programs loaded it")
    print("  2  Show it again for every program")
    g = input("Choose 1-2 (press Enter to keep this): ").strip()
    if g == "1":
        view["group"] = True
    elif g == "2":
        view["group"] = False
    elif g:
        print("That was not 1 or 2, so I left the grouping as it was.")
    print(f"Now showing: {view_text()}")


def short_list(text, limit=5):
    names = text.split("; ")
    if len(names) <= limit:
        return text
    return "; ".join(names[:limit]) + f"; and {len(names) - limit} more"


def print_details(procs, include_windows):
    rows = apply_view(get_rows(procs, include_windows))
    if not rows:
        print("Nothing matches this view. Option 5 changes it.")
        return
    for r in rows:
        n = r["seen_in_processes"]
        seen = ""
        if view["group"]:
            word = "process" if n == 1 else "processes"
            seen = f"  (seen in {n} {word})"
        print(f"{paint('[' + r['risk'] + ']', r['risk'])} score {r['score']}{seen}")
        print(f"      {r['module']}")
        print(f"      signer: {r['signer']} ({r['signature']})")
        if r["reasons"]:
            print(f"      reasons: {r['reasons']}")
        print(f"      loaded by: {short_list(r['processes'])}")
    unit = "files" if view["group"] else "rows"
    print(f"\n{len(rows)} {unit} shown ({view_text()}).")
    print("A score means the file matched the rules. It does not mean it is malware.")


def save_csv(rows, filename):
    try:
        with open(filename, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        print(f"Saved {len(rows)} rows to {os.path.abspath(filename)}")
    except PermissionError:
        print(f"Could not write {filename}. If Excel has it open, close it and try again.")


def print_summary(procs):
    files = group_by_file([r for p in procs for r in p["rows"]])
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "OK": 0}
    for r in files:
        counts[r["risk"]] += 1
    total_modules = sum(p["total"] for p in procs)
    print(f"\nScanned {len(procs)} process(es), {total_modules} module loads in total.")
    print(f"Unique files outside Windows/Program Files folders: {len(files)}")
    print("Flagged (MEDIUM or HIGH): "
          f"{paint('HIGH ' + str(counts['HIGH']), 'HIGH')}, "
          f"{paint('MEDIUM ' + str(counts['MEDIUM']), 'MEDIUM')}")
    print("Not flagged: "
          f"{paint('LOW ' + str(counts['LOW']), 'LOW')}, "
          f"{paint('OK ' + str(counts['OK']), 'OK')} "
          "(option 5 if you want to see them)")
    print(f"Skipped (protected or already closed): {stats['skipped']}")


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main():
    if os.name != "nt":
        raise SystemExit("DLLGuard only works on Windows.")

    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help", "/?"):
        print(USAGE)
        return

    target = sys.argv[1] if len(sys.argv) > 1 else None
    print(f"Running as administrator: {'yes' if is_admin() else 'no'}")

    if target is None:
        # PID 0 is System Idle, PID 4 is the kernel. Neither has a DLL list.
        pids = [p.pid for p in psutil.process_iter() if p.pid not in (0, 4)]
        base = "all_processes"
        print(f"Scanning all {len(pids)} running processes...")
        print("To scan one program instead: py dllguard.py notepad.exe\n")
    else:
        if target.isdigit():
            pids = [int(target)]
        else:
            pids = find_pids(target)
        if not pids:
            raise SystemExit(f"{target} is not running.")
        base = os.path.splitext(target)[0]
        print(f"Found {len(pids)} copy(ies) of {target}. Scanning...\n")

    procs = [p for p in (collect_pid(pid) for pid in pids) if p]
    if not procs:
        raise SystemExit("Nothing could be scanned.")

    score_collected(procs)
    print_summary(procs)

    while True:
        print("\nWhat do you want to do next?")
        print("  1  Show results (current view)")
        print("  2  Show results, including Windows and Program Files (slow the first time)")
        print("  3  Save a CSV of the current view")
        print("  4  Save a CSV that also includes Windows and Program Files")
        print("  5  Change the view (levels, order, grouping)")
        print("  6  Quit")
        print(f"Current view: {view_text()}")
        try:
            choice = input("Choose 1-6: ").strip()
        except EOFError:
            print("I cannot read typing here. Open a normal PowerShell window and run it there.")
            break
        except KeyboardInterrupt:
            break

        if choice == "1":
            print_details(procs, include_windows=False)
        elif choice == "2":
            print_details(procs, include_windows=True)
        elif choice == "3":
            save_csv(apply_view(get_rows(procs, include_windows=False)),
                     f"dllguard_{base}_findings.csv")
        elif choice == "4":
            save_csv(apply_view(get_rows(procs, include_windows=True)),
                     f"dllguard_{base}_everything.csv")
        elif choice == "5":
            change_view()
        elif choice == "6":
            break
        else:
            print("Type a number from 1 to 6.")


if __name__ == "__main__":
    main()
