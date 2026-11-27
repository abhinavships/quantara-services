"""Digital twin: the same lumped thermal model the simulator uses, run as the cloud's what-if engine.
C dT/dt = KGEN*P^2 + extra - (KNAT + KFLOW*flow/NOMFLOW)(T - Tamb). Sub-steps never exceed 5 model-seconds."""
C, KGEN, KNAT, KFLOW, NOMFLOW = 25.0, 0.0005, 0.05, 0.25, 12.0
MAX_SUBSTEP_S = 5.0
LIMITS = {"warn": 45.0, "derate": 50.0, "critical": 58.0}


def advance(T, P, flow, tamb, extra, seconds, kgen_mult=1.0):
    """Integrate `seconds` of model time in sub-steps <= MAX_SUBSTEP_S."""
    n = max(1, int(-(-seconds // MAX_SUBSTEP_S)))
    dt = seconds / n
    for _ in range(n):
        q_in = KGEN * kgen_mult * P * P + extra
        q_out = (KNAT + KFLOW * flow / NOMFLOW) * (T - tamb)
        T += dt * (q_in - q_out) / C
    return T


def replay_rmse(ring, extra_kw, tamb):
    """Replay the observed ring with measured power/flow; RMSE of predicted vs measured temperature."""
    pts = [r for r in ring if "Battery.Temp" in r and "Power.kW" in r and "Coolant.Flow" in r]
    if len(pts) < 3: return None
    T, se, n = pts[0]["Battery.Temp"], 0.0, 0
    for a, b in zip(pts, pts[1:]):
        T = advance(T, a["Power.kW"], a["Coolant.Flow"], tamb, extra_kw, max(1.0, (b["t"] - a["t"])))
        se += (T - b["Battery.Temp"]) ** 2; n += 1
    return (se / n) ** 0.5


def fit_hidden_heat(ring, tamb):
    """Grid-search the unexplained heat source (kW). 0 means measured power+flow fully explain the rise."""
    best = None
    for i in range(0, 41):
        e = i * 0.1
        r = replay_rmse(ring, e, tamb)
        if r is not None and (best is None or r < best[1]): best = (e, r)
    return best


def time_to(T0, P, flow, tamb, extra, limit, horizon=900, step=5):
    T = T0
    for t in range(0, horizon + 1, step):
        if T >= limit: return t
        T = advance(T, P, flow, tamb, extra, step)
    return None


def evaluate(ring, tamb=25.0):
    """-> twin verdict for one incident freeze-frame."""
    if not ring or len(ring) < 3: return {"ok": False, "why": "ring too short"}
    nominal = replay_rmse(ring, 0.0, tamb)
    extra, fit = fit_hidden_heat(ring, tamb)
    last = ring[-1]
    T0, P, flow = last["Battery.Temp"], last["Power.kW"], last["Coolant.Flow"]
    hidden = extra >= 0.5 and nominal is not None and nominal > max(0.3, 2 * fit)
    plans = {}
    for cap in (1.0, 0.7, 0.4):
        ttl = time_to(T0, P * cap * cap if cap < 1 else P, flow, tamb, extra if hidden else 0.0, LIMITS["derate"])
        plans[str(cap)] = ttl
    safe = [c for c in ("1.0", "0.7", "0.4") if plans[c] is None]
    return {"ok": True, "rmse_nominal": round(nominal, 3), "rmse_fit": round(fit, 3), "hidden_heat_kw": round(extra, 2),
            "hidden_heat_confirmed": bool(hidden), "t_now": round(T0, 2), "time_to_derate_s": plans,
            "recommended_cap": float(safe[0]) if safe else 0.4, "substep_max_s": MAX_SUBSTEP_S}
