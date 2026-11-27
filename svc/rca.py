"""Root-cause analysis: posterior = likelihood(evidence | cause) x learned prior. Plus fleet correlation and the
learning loop (technician feedback -> priors; recurring cloud-solved causes -> proposed rulebook change)."""
import copy
import math
from collections import defaultdict, deque

CAUSES = ("pump_fault", "cell_heating", "high_load", "sensor_fault", "efficiency_degradation",
          "grid_outage", "can_attack", "calibration_tamper", "unknown")
clip = lambda x: max(0.0, min(1.0, x))


def base_cause(c): return (c or "unknown").split(":")[0]


def likelihoods(inc, frame, ctx):
    ev, c0 = inc.get("evidence", {}), base_cause(inc.get("cause"))
    fr = ev.get("flow_ratio", 1.0)
    hr, pf = ev.get("heat_resid", 0.0), ev.get("power_frac", 0.5)
    lk = {c: 0.05 for c in CAUSES}
    lk["pump_fault"] = clip((0.85 - fr) / 0.45)
    lk["cell_heating"] = clip(hr / 0.05) * (1.0 if fr > 0.75 else 0.3)
    lk["high_load"] = 0.85 if fr >= 0.8 and pf >= 0.6 and hr < 0.02 else 0.05
    for c in ("sensor_fault", "efficiency_degradation", "grid_outage", "can_attack", "calibration_tamper"):
        if c0 == c: lk[c] = 0.9
    if c0 in lk and c0 not in ("unknown", "pump_fault", "high_load"): lk[c0] = max(lk[c0], 0.9)
    peers = (ctx or {}).get("peers_same_cause", 0)
    if peers >= 3 and c0 in lk: lk[c0] = max(lk[c0], 0.9)          # fleet pattern corroborates
    return lk


class Priors:
    """Laplace-smoothed counts of technician-confirmed causes."""
    def __init__(self): self.n = defaultdict(int)
    def get(self):
        tot = sum(self.n.values()) + len(CAUSES)
        return {c: (self.n[c] + 1) / tot for c in CAUSES}
    def confirm(self, cause): self.n[base_cause(cause)] += 1


class Rca:
    def __init__(self, priors=None): self.priors = priors or Priors()

    def analyse(self, m):
        inc, ff = m.get("incident", {}), m.get("freeze_frame", {})
        ring = ff.get("ring_5min", [])
        lk, pr = likelihoods(inc, ring[-1] if ring else {}, m.get("context", {})), self.priors.get()
        post = {c: lk[c] * pr[c] for c in CAUSES}
        z = sum(post.values()) or 1.0
        hyp = sorted(({"cause": c, "likelihood": round(lk[c], 3), "prior": round(pr[c], 4),
                       "posterior": round(post[c] / z, 4)} for c in CAUSES), key=lambda h: -h["posterior"])
        return {"kind": "rca", "incident_id": inc.get("id"), "vehicle_id": m.get("vehicle_id"), "ts": m.get("ts"),
                "edge_cause": inc.get("cause"), "reasons": m.get("reasons", []), "hypotheses": hyp[:5],
                "top": hyp[0]["cause"], "margin": round(hyp[0]["posterior"] - hyp[1]["posterior"], 4),
                "ring": ring, "ambient_c": (m.get("context", {}).get("weather") or {}).get("ambient_c", 25.0),
                "position": m.get("context", {}).get("position"), "evidence": inc.get("evidence", {}),
                "edge_actions": inc.get("actions", []), "security": m.get("kind") == "security"}


class FleetCorrelator:
    def __init__(self, window_s=600, min_vehicles=3, cooldown_s=600):
        self.w, self.k, self.cd, self.ev, self.last = window_s, min_vehicles, cooldown_s, deque(), {}

    def add(self, ts, vid, cause):
        c = base_cause(cause)
        self.ev.append((ts, vid, c))
        while self.ev and ts - self.ev[0][0] > self.w: self.ev.popleft()
        vs = {v for t, v, cc in self.ev if cc == c}
        if len(vs) >= self.k and ts - self.last.get(c, -1e18) > self.cd:
            self.last[c] = ts
            return {"kind": "fleet_incident", "cause": c, "vehicles": sorted(vs), "window_s": self.w, "ts": ts,
                    "suggestion": "batch/environment suspected" if c != "can_attack" else "coordinated attack suspected"}


class Learning:
    """Recurring cloud-solved issues -> proposed (never auto-applied) rulebook change."""
    MANDATORY_KEEP = ("temp_warn", "temp_derate", "temp_critical", "flow_low_hot")

    def __init__(self, min_cases=3, base=None):
        self.min, self.cases, self.proposed, self.base = min_cases, defaultdict(list), set(), base

    def record_solved(self, cause, evidence):
        c = base_cause(cause)
        self.cases[c].append(evidence)
        if len(self.cases[c]) >= self.min and c not in self.proposed and c in ("cell_heating",):
            self.proposed.add(c)
            return self.propose(c)

    def propose(self, cause):
        ev = self.cases[cause]
        thr = round(0.8 * min(e.get("heat_resid", 0.05) for e in ev), 4) or 0.01
        rb = copy.deepcopy(self.base)
        rb["version"] += 1
        rb["rules"].append({"id": f"learned_{cause}", "mandatory": False, "cause": cause,
                            "when": f"heat_resid > {thr} and flow_ratio > 0.75 and temp > warn - 8",
                            "clear": "heat_resid < " + str(round(thr / 2, 4)), "dwell": 3, "clear_hold": 10,
                            "action": {"type": "derate", "value": 0.7}})
        return {"kind": "rulebook_proposal", "cause": cause, "cases": len(ev), "rulebook": rb,
                "rationale": f"{len(ev)} cloud-solved {cause} incidents; derate earlier at the edge",
                "status": "pending_approval"}
