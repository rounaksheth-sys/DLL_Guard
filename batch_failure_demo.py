"""
Demo for the report: what happens when ONE file in a batch of 50 makes the
signature check time out?

This script does not need a real stuck file. It replaces the PowerShell call
with a fake one that "times out" whenever the batch contains the stuck file,
and answers "Valid" for everything else. It then runs the real
check_signatures_batch() from dllguard.py on that batch.

Put this file next to dllguard.py and run:   py batch_failure_demo.py
Run it once with the OLD batch function and once with the fixed one, and keep
both outputs for the report.
"""
import json
import re
import subprocess

import dllguard

STUCK = r"c:\users\test\onedrive\stuck_file.dll"
APP_FOLDER = "c:\\users\\test\\appdata\\local\\app\\"
paths = [APP_FOLDER + f"file{i}.dll" for i in range(49)] + [STUCK]


def fake_run(cmd, **kwargs):
    script = cmd[-1]
    list_path = re.search(r"Get-Content -LiteralPath '([^']+)'", script).group(1)
    with open(list_path, encoding="utf-8") as f:
        listed = [line.strip() for line in f if line.strip()]
    if any("stuck_file" in p for p in listed):
        raise subprocess.TimeoutExpired(cmd, 180)      # PowerShell "hangs"
    rows = []
    for i, p in enumerate(listed, 1):
        row = {"Status": "Valid", "Signer": "CN=Example Corp"}
        if "Index=$i" in script:                       # fixed version asks for Index
            row["Index"] = i
        else:                                          # old version asks for Path
            row["Path"] = p
        rows.append(row)

    class Result:
        stdout = json.dumps(rows)
    return Result()


dllguard.subprocess.run = fake_run

result = dllguard.check_signatures_batch(paths)
errors = [p for p, s in result.items() if s["Status"] == "Error"]
valid = [p for p, s in result.items() if s["Status"] == "Valid"]

print(f"Batch: {len(paths)} files, and 1 of them (stuck_file.dll) makes PowerShell hang")
print(f"Marked Valid: {len(valid)}")
print(f"Marked Error: {len(errors)}")

# What that does to the score of a perfectly normal file in the same batch
normal = paths[0]
good_sig = {"Status": "Valid", "Signer": "CN=Example Corp"}
for label, sig in (("with the correct result", good_sig), ("with the result it received", result[normal])):
    pts, reasons = dllguard.score(normal, APP_FOLDER, "Example Corp", sig)
    print(f"file0.dll {label}: score {pts} = {dllguard.risk_label(pts)}")
