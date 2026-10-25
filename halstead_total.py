import json, subprocess, sys, math
EXC = "venv/*,.venv/*,tests/*,migrations/*,exp1/*"
out = subprocess.run([sys.executable, "-m", "radon", "hal", "-j", ".", "-e", EXC],
                     capture_output=True, text=True).stdout
data = json.loads(out)
rows = []
for name, v in data.items():
    if "error" in v:
        continue
    t = v.get("total", v)
    rows.append((name, t["h1"], t["h2"], t["N1"], t["N2"], t["effort"]))
h1 = sum(r[1] for r in rows); h2 = sum(r[2] for r in rows)
N1 = sum(r[3] for r in rows); N2 = sum(r[4] for r in rows)
eta = h1 + h2; N = N1 + N2
V = N * math.log2(eta)
D = (h1 / 2) * (N2 / h2)
print(f"Файлів: {len(rows)}")
print(f"sum h1={h1}  sum h2={h2}  eta={eta}")
print(f"N1={N1}  N2={N2}  N={N}")
print(f"V={V:.1f}  D={D:.2f}  E={V*D:.1f}")
print("\nТОП-10 файлів за E:")
for r in sorted(rows, key=lambda r: r[5], reverse=True)[:10]:
    print(f"{r[0]:35s} E={r[5]:10.1f}")
