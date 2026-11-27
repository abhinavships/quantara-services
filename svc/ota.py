"""Cloud command return path: guarded signing, consent/OEM approvals, staged rollouts with halt + rollback."""
import itertools
import math
import time

from quantara_core import crypto

NEEDS_CONSENT = {"behavioural", "software", "raise_power", "security_patch", "rulebook_update"}
NEEDS_OEM = {"security_patch", "software"}
GUARDS = {"derate": ("limit", 0.4, 1.0), "limp": ("speed_frac", 0.2, 1.0), "raise_power": ("limit", 0.4, 1.0)}
KINDS = NEEDS_CONSENT | set(GUARDS) | {"rollback"}


class Refused(Exception): pass


class Issuer:
    """The only place commands are signed. Refuses out-of-guard, unknown or un-approved commands."""
    def __init__(self, priv_b64, ttl_s=300, clock=time.time):
        self.priv, self.ttl, self.clock, self.counters = priv_b64, ttl_s, clock, {}

    def issue(self, vid, kind, params, consent=None, oem=None):
        if kind not in KINDS: raise Refused(f"unknown kind {kind}")
        if kind in GUARDS:
            f, lo, hi = GUARDS[kind]
            if not (isinstance(params.get(f), (int, float)) and lo <= params[f] <= hi): raise Refused("out of guard range")
        if kind in NEEDS_CONSENT and not (consent and consent.get("decision") == "approved"): raise Refused("consent required")
        if kind in NEEDS_OEM and not (oem and oem.get("approved")): raise Refused("OEM approval required")
        c = self.counters.get(vid, 0) + 1
        self.counters[vid] = c
        if consent: consent = {**consent, "counter": c, "vehicle_id": vid}      # proofs are bound to this counter
        if oem: oem = {**oem, "counter": c}
        return crypto.make_command(self.priv, vid, kind, params, c, self.ttl, consent, oem, self.clock())


class Rollout:
    def __init__(self, rid, rulebook, vehicles, consented, issuer, stages=(5, 25, 100), halt_fail=0.2):
        self.id, self.rb, self.vs, self.ok_consent, self.iss = rid, rulebook, list(vehicles), set(consented), issuer
        self.stages, self.halt, self.stage = stages, halt_fail, -1
        self.sent, self.res, self.status, self.skipped = {}, {}, "running", set()

    def _target(self, pct): return self.vs[:max(1, math.ceil(len(self.vs) * pct / 100))] if self.vs else []

    def advance(self):
        """Send the next stage. Returns commands. Evaluates the previous stage first (halt/rollback on failure)."""
        if self.status != "running": return []
        if self.stage >= 0 and not self._stage_done():
            return []
        if self.stage >= 0 and self._fail_rate() > self.halt:
            self.status = "halted"
            return self._rollback()
        self.stage += 1
        if self.stage >= len(self.stages):
            self.status = "complete"; return []
        cmds = []
        for v in self._target(self.stages[self.stage]):
            if v in self.sent or v in self.skipped: continue
            if v not in self.ok_consent: self.skipped.add(v); continue
            cmds.append(self.iss.issue(v, "rulebook_update", {"rulebook": self.rb},
                                       consent={"decision": "approved", "by": "owner"}))
            self.sent[v] = cmds[-1]["counter"]
        return cmds

    def on_result(self, vid, ok, why):
        if vid in self.sent: self.res[vid] = (ok, why)

    def _stage_done(self): return all(v in self.res for v in self.sent)
    def _fail_rate(self):
        done = [r for r in self.res.values()]
        return (sum(1 for ok, _ in done if not ok) / len(done)) if done else 0.0

    def _rollback(self):
        self.status = "halted"
        return [self.iss.issue(v, "rollback", {}) for v, (ok, _) in self.res.items() if ok]

    def snapshot(self):
        return {"kind": "rollout_status", "id": self.id, "status": self.status, "stage": self.stage,
                "pct": self.stages[self.stage] if 0 <= self.stage < len(self.stages) else None,
                "sent": len(self.sent), "applied": sum(1 for ok, _ in self.res.values() if ok),
                "failed": sum(1 for ok, _ in self.res.values() if not ok), "skipped_no_consent": len(self.skipped)}


class OtaService:
    """cloud.twin -> decisions; cloud.ota -> approvals / rollouts / command results. Emits commands.out, notify.out."""
    def __init__(self, priv_b64, clock=time.time):
        self.iss, self.clock = Issuer(priv_b64, clock=clock), clock
        self.pending, self.rollouts, self.rid = {}, {}, itertools.count(1)
        self.fleet, self.stats = set(), {"commands": 0, "refused": 0, "consent_requests": 0}

    def _cmd(self, vid, kind, params, **kw):
        try:
            c = self.iss.issue(vid, kind, params, **kw); self.stats["commands"] += 1
            return [("commands.out", c, vid)]
        except Refused as e:
            self.stats["refused"] += 1
            return [("notify.out", {"kind": "refused", "vehicle_id": vid, "command": kind, "why": str(e)}, vid)]

    def _notify(self, vid, ch, text, **x): return ("notify.out", {"kind": "notice", "vehicle_id": vid, "channel": ch, "text": text, **x}, vid)

    def process(self, topic, m):
        k = m.get("kind")
        if topic == "cloud.twin": return self._twin(m)
        if topic == "cloud.fleet" and k == "summary": self.fleet.add(m.get("vehicle_id")); return []
        if topic != "cloud.ota": return []
        if k == "consent_decision": return self._consent(m)
        if k == "oem_approval": return self._oem(m)
        if k == "command_result": return self._result(m)
        if k == "rulebook_approve": return self._rollout_start(m)
        if k == "rollout_tick": return self._tick(m)
        return []

    def _twin(self, m):
        vid, cause = m["vehicle_id"], m.get("final_cause")
        if m.get("security"):
            return [self._notify(vid, "security", f"security incident {m.get('edge_cause')}: edge contained it", incident=m.get("incident_id"))]
        out = []
        cap = m.get("recommended_cap", 1.0)
        if cap < 1.0 and "derate" not in " ".join(m.get("edge_actions", [])):
            out += self._cmd(vid, "derate", {"limit": cap})
        if cause == "efficiency_degradation":
            rid = f"req-{vid}-{self.stats['consent_requests']+1}"
            self.pending[rid] = {"vehicle_id": vid, "kind": "behavioural", "params": {"mode": "eco"}, "consent": None, "oem": None}
            self.stats["consent_requests"] += 1
            out.append(self._notify(vid, "driver", "Efficiency is falling. Enable eco mode?", request_id=rid))
        if cap < 1.0 or cause in ("pump_fault", "cell_heating"):
            out.append(self._notify(vid, "driver", f"Battery cooling issue ({cause}); power reduced to {int(cap*100)}%."))
            out.append(self._notify(vid, "fleet_ops", f"{vid}: {cause} validated by twin", incident=m.get("incident_id")))
        return out

    def _consent(self, m):
        p = self.pending.get(m.get("request_id"))
        if not p: return [("notify.out", {"kind": "refused", "why": "unknown request"}, None)]
        if m.get("decision") != "approved":
            del self.pending[m["request_id"]]
            return [self._notify(p["vehicle_id"], "fleet_ops", "owner declined", request_id=m["request_id"])]
        p["consent"] = {"decision": "approved", "by": m.get("by", "owner")}
        return self._maybe_issue(m["request_id"])

    def _oem(self, m):
        p = self.pending.get(m.get("request_id"))
        if not p: return []
        p["oem"] = {"approved": bool(m.get("approved")), "by": m.get("by", "oem")}
        return self._maybe_issue(m["request_id"])

    def _maybe_issue(self, rid):
        p = self.pending[rid]
        if p["kind"] in NEEDS_OEM and not p["oem"]: return []
        out = self._cmd(p["vehicle_id"], p["kind"], p["params"], consent=p["consent"], oem=p["oem"])
        del self.pending[rid]
        return out

    def _rollout_start(self, m):
        rid = f"ro-{next(self.rid)}"
        vs = m.get("vehicles") or sorted(self.fleet)
        ro = self.rollouts[rid] = Rollout(rid, m["rulebook"], vs, m.get("consented", vs), self.iss,
                                          halt_fail=m.get("halt_fail", 0.2))
        return self._tick({"rollout": rid})

    def _tick(self, m):
        ro = self.rollouts.get(m.get("rollout"))
        if not ro: return []
        out = [("commands.out", c, c["vehicle_id"]) for c in ro.advance()]
        self.stats["commands"] += len(out)
        return out + [("cloud.ota", ro.snapshot(), None)]

    def _result(self, m):
        out = []
        for ro in self.rollouts.values(): ro.on_result(m.get("vehicle_id"), m.get("ok"), m.get("why"))
        for ro in self.rollouts.values():
            if ro.status == "running" and ro.sent and ro._stage_done():
                out += self._tick({"rollout": ro.id})          # auto-advance once a stage reports in
        return out
