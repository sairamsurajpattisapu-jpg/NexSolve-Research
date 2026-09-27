import os
import re

patterns = [
    r"mean_tcp_rtt",
    r"zero-fill",
    r"zero_fill",
    r"synthetic",
    r"demo",
    r"label.*leak",
    r"target.*feature",
]

search_dirs = ["ml", "nexsolve_core"]

print("=== FABRICATION AND FALLBACK AUDIT ===")
found_any = False
for d in search_dirs:
    for root, dirs, files in os.walk(d):
        for f in files:
            if f.endswith(".py"):
                p = os.path.join(root, f)
                content = open(p, encoding="utf-8", errors="ignore").read()
                for pat in patterns:
                    matches = list(re.finditer(pat, content, re.IGNORECASE))
                    if matches:
                        found_any = True
                        print(f"{p}: '{pat}' matched {len(matches)} times")
                        for m in matches[:3]:
                            start = max(0, m.start() - 40)
                            end = min(len(content), m.end() + 40)
                            snippet = content[start:end].replace('\n', ' ')
                            print(f"    snippet: ...{snippet}...")

if not found_any:
    print("None found.")
