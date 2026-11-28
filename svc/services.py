"""Per-role wrappers: process(topic_short, msg) -> [(out_topic_short, msg, key)]. One image, ROLE selects."""
from . import llm, route, twin
from .rca import FleetCorrelator, Learning, Rca, base_cause

DEFAULT_RULEBOOK = {"version": 1, "limits": {"warn": 45.0, "derate": 50.0, "critical": 58.0}, "rules": [
    {"id": "temp_warn", "mandatory": True, "when": "temp > warn", "clear": "temp < warn - 3", "dwell": 2, "clear_hold": 5, "action": {"type": "alert", "value": 1}},
    {"id": "temp_derate", "mandatory": True, "when": "temp > derate", "clear": "temp < derate - 3", "dwell": 2, "clear_hold": 8, "action": {"type": "derate", "value": 0.7}},
    {"id": "temp_critical", "mandatory": True, "when": "temp > critical", "clear": "temp < critical - 4", "dwell": 1, "clear_hold": 10, "action": {"type": "derate", "value": 0.4}},
    {"id": "flow_low_hot", "mandatory": True, "when": "flow_ratio < 0.5 and temp > warn - 5", "clear": "flow_ratio > 0.7 or temp < warn - 10", "dwell": 3, "clear_hold": 8, "action": {"type": "derate", "value": 0.6}}]}


class RcaService:
    def __init__(self):
        self.rca, self.fleet, self.learn = Rca(), FleetCorrelator(), Learning(base=DEFAULT_RULEBOOK)
        self.stats = {"rca": 0, "feedback": 0, "proposals": 0}

    def process(self, topic, m):
        k = m.get("kind")
        if topic in ("cloud.escalations", "cloud.security"):
            r = self.rca.analyse(m); self.stats["rca"] += 1
            op = llm.second_opinion(r)
            if op: r["llm"] = op; self.stats["llm"] = self.stats.get("llm", 0) + 1
            out = [("cloud.rca", r, m.get("vehicle_id"))]
            f = self.fleet.add(m.get("ts", 0), m.get("vehicle_id"), m.get("incident", {}).get("cause"))
            return out + ([("cloud.fleet", f, None)] if f else [])
        if topic == "cloud.ota" and k == "feedback":
            self.rca.priors.confirm(m["confirmed_cause"]); self.stats["feedback"] += 1
            return [("cloud.rca", {"kind": "priors_update", "cause": base_cause(m["confirmed_cause"]),
                                   "priors": self.rca.priors.get()}, None)]
        if topic == "cloud.twin" and m.get("hidden_heat_confirmed") and "unattributed" in m.get("reasons", []):
            p = self.learn.record_solved(m["final_cause"], m.get("evidence", {}))
            if p: self.stats["proposals"] += 1; return [("cloud.ota", p, None)]
        return []


class TwinService:
    def __init__(self): self.stats = {"twin": 0}

    def process(self, topic, m):
        if topic != "cloud.rca" or m.get("kind") != "rca": return []
        self.stats["twin"] += 1
        v = twin.evaluate(m.get("ring", []), m.get("ambient_c", 25.0)) if not m.get("security") else {"ok": False, "why": "non-thermal"}
        hyp = [h["cause"] for h in m["hypotheses"]]
        final = m["top"]
        if v.get("ok"):
            if v["hidden_heat_confirmed"]: final = "cell_heating"
            elif final == "cell_heating": final = next((c for c in hyp if c != "cell_heating"), "unknown")
        out = {"kind": "twin", "incident_id": m["incident_id"], "vehicle_id": m["vehicle_id"], "ts": m["ts"],
               "final_cause": final, "rca_top": m["top"], "edge_cause": m["edge_cause"], "reasons": m["reasons"],
               "security": m["security"], "evidence": m["evidence"], "edge_actions": m["edge_actions"],
               "position": m.get("position"), "ambient_c": m.get("ambient_c"),
               "last": (m["ring"][-1] if m.get("ring") else {}), "recommended_cap": v.get("recommended_cap", 1.0),
               "hidden_heat_confirmed": v.get("hidden_heat_confirmed", False), "twin": v}
        return [("cloud.twin", out, m["vehicle_id"])]


class RouteService:
    def __init__(self): self.stations, self.stats = [], {"plans": 0}

    def process(self, topic, m):
        if topic == "cloud.fleet" and m.get("kind") == "feeds":
            self.stations = (m.get("grid") or {}).get("stations", []); return []
        if topic != "cloud.twin" or m.get("security"): return []
        cap, cause = m.get("recommended_cap", 1.0), m.get("final_cause")
        if cap >= 1.0 and cause != "grid_outage": return []
        last = m.get("last", {})
        pl = route.plan(m.get("position"), last.get("Battery.SoC", 0.5), last.get("Battery.kmPerKwh", 6.0), cap, self.stations)
        self.stats["plans"] += 1
        return [("cloud.route", {"kind": "route", "vehicle_id": m["vehicle_id"], "incident_id": m["incident_id"],
                                 "reason": cause, "cap": cap, "ts": m["ts"], **pl}, m["vehicle_id"])]
