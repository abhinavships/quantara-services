"""Route optimiser: pick a reachable, online charging station for a vehicle that is derated / cannot reach its
usual one. Straight-line distance x detour factor (no road graph); reserve margin; derate cuts usable range."""
import math

PACK_KWH, DETOUR, RESERVE = 60.0, 1.3, 0.9


def hav(a, b, c, d):
    p = math.pi / 180
    x = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 12742 * math.asin(math.sqrt(x))


def plan(pos, soc, kpk, cap, stations, avg_kmh=40.0):
    if not pos: return {"ok": False, "why": "no position"}
    rng = max(0.0, soc * PACK_KWH * kpk) * (1.0 if cap >= 1 else 0.85 + 0.15 * cap)
    cands = []
    for s in stations:
        if not s.get("online"): continue
        d = hav(pos[0], pos[1], s["lat"], s["lon"]) * DETOUR
        cands.append({"station": s["id"], "distance_km": round(d, 2), "eta_min": round(60 * d / (avg_kmh * max(cap, 0.4)), 1),
                      "reachable": d <= rng * RESERVE})
    cands.sort(key=lambda c: c["distance_km"])
    ok = [c for c in cands if c["reachable"]]
    if ok: return {"ok": True, "range_km": round(rng, 1), "choice": ok[0], "alternatives": ok[1:3]}
    return {"ok": False, "range_km": round(rng, 1), "why": "no reachable online station", "nearest": cands[:1],
            "advice": "stop safely and request assistance"}
