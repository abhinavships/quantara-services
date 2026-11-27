import pytest
from quantara_core import crypto
from quantara_core.bus import MemBus
from svc import route, twin
from svc.ota import Issuer, OtaService, Refused, Rollout
from svc.rca import FleetCorrelator, Learning, Priors, Rca
from svc.services import DEFAULT_RULEBOOK, RcaService, RouteService, TwinService

PRIV, PUB = crypto.gen_keypair()


def make_ring(extra=0.0, flow=12.0, P=40.0, T0=35.0, n=60, tamb=25.0):
    ring, T = [], T0
    for i in range(n):
        ring.append({"t": i * 5, "Battery.Temp": T, "Power.kW": P, "Coolant.Flow": flow, "Pump.Duty": 0.8,
                     "Battery.SoC": 0.6, "Battery.kmPerKwh": 6.0})
        T = twin.advance(T, P, flow, tamb, extra, 5.0)
    return ring


def esc(vid="V1", cause="unknown", ev=None, ring=None, reasons=("unattributed",), kind="escalation", ts=100.0, ctx=None):
    return {"kind": kind, "vehicle_id": vid, "ts": ts, "reasons": list(reasons),
            "incident": {"id": f"{vid}-1", "cause": cause, "confidence": 0.5, "status": "open", "actions": ["alert"],
                         "evidence": ev or {"flow_ratio": 1.0, "heat_resid": 0.08, "power_frac": 0.5, "temp": 47}},
            "freeze_frame": {"ring_5min": ring if ring is not None else make_ring(2.0)},
            "context": ctx or {"weather": {"ambient_c": 25.0}, "position": [12.97, 77.59]}}


# ---------------- twin ----------------
def test_substep_never_exceeds_5s(monkeypatch):
    steps = []
    orig = twin.advance
    # one call of 60 s must be integrated in sub-steps <= 5 s: compare against two 30 s halves (consistent integration)
    a = twin.advance(30, 40, 6, 25, 1.0, 60)
    b = twin.advance(twin.advance(30, 40, 6, 25, 1.0, 30), 40, 6, 25, 1.0, 30)
    assert abs(a - b) < 1e-9 and twin.MAX_SUBSTEP_S <= 5


def test_twin_recovers_hidden_heat_source():
    v = twin.evaluate(make_ring(extra=2.0))
    assert v["hidden_heat_confirmed"] and abs(v["hidden_heat_kw"] - 2.0) <= 0.3


def test_twin_flow_fault_is_explained_by_flow_not_hidden_heat():
    v = twin.evaluate(make_ring(extra=0.0, flow=2.0, P=45.0))
    assert v["ok"] and not v["hidden_heat_confirmed"]


def test_twin_recommends_least_restrictive_safe_cap():
    v = twin.evaluate(make_ring(extra=3.0, flow=3.0, P=60.0, T0=44.0, n=30))
    assert v["recommended_cap"] in (0.7, 0.4) and v["recommended_cap"] <= 0.7
    cool = twin.evaluate(make_ring(extra=0.0, flow=12.0, P=10.0, T0=30.0))
    assert cool["recommended_cap"] == 1.0


def test_twin_short_ring_rejected():
    assert twin.evaluate([])["ok"] is False


# ---------------- rca ----------------
def test_rca_flow_collapse_points_to_pump_fault():
    r = Rca().analyse(esc(cause="pump_fault", ev={"flow_ratio": 0.3, "heat_resid": 0.0, "power_frac": 0.6}, reasons=["low_confidence"]))
    assert r["top"] == "pump_fault" and sum(h["posterior"] for h in r["hypotheses"]) <= 1.0001


def test_rca_hidden_heat_with_normal_flow_points_to_cell_heating():
    r = Rca().analyse(esc(cause="unknown", ev={"flow_ratio": 1.0, "heat_resid": 0.1, "power_frac": 0.5}))
    assert r["top"] == "cell_heating"


def test_priors_learn_from_feedback_and_change_posterior():
    rca = Rca()
    inc = esc(cause="unknown", ev={"flow_ratio": 0.82, "heat_resid": 0.02, "power_frac": 0.4})   # genuinely ambiguous
    before = {h["cause"]: h["posterior"] for h in rca.analyse(inc)["hypotheses"]}
    for _ in range(30): rca.priors.confirm("cell_heating")
    after = {h["cause"]: h["posterior"] for h in rca.analyse(inc)["hypotheses"]}
    assert after["cell_heating"] > before["cell_heating"] + 0.3
    assert max(after, key=after.get) == "cell_heating"
    assert abs(sum(rca.priors.get().values()) - 1) < 1e-9


def test_fleet_correlation_fires_once_per_window():
    f = FleetCorrelator(window_s=600, min_vehicles=3)
    assert f.add(1, "A", "pump_fault") is None and f.add(2, "B", "pump_fault") is None
    hit = f.add(3, "C", "pump_fault")
    assert hit and hit["vehicles"] == ["A", "B", "C"]
    assert f.add(4, "D", "pump_fault") is None                      # cooldown
    assert FleetCorrelator().add(1, "A", "can_attack:flood") is None


def test_fleet_window_expires_old_events():
    f = FleetCorrelator(window_s=100, min_vehicles=3)
    f.add(0, "A", "x"); f.add(1, "B", "x")
    assert f.add(500, "C", "x") is None


def test_learning_proposes_guard_valid_rulebook_after_n_cases():
    L = Learning(min_cases=3, base=DEFAULT_RULEBOOK)
    assert L.record_solved("cell_heating", {"heat_resid": 0.09}) is None
    assert L.record_solved("cell_heating", {"heat_resid": 0.07}) is None
    p = L.record_solved("cell_heating", {"heat_resid": 0.1})
    rb = p["rulebook"]
    assert p["status"] == "pending_approval" and rb["version"] == 2
    new = [r for r in rb["rules"] if r["id"].startswith("learned_")][0]
    assert new["action"]["type"] == "derate" and 0.4 <= new["action"]["value"] <= 1.0 and not new["mandatory"]
    old = {r["id"]: r for r in DEFAULT_RULEBOOK["rules"]}
    for r in rb["rules"]:
        if r["id"] in old: assert r == old[r["id"]]                  # mandatory rules untouched
    assert all(rb["limits"][k] <= DEFAULT_RULEBOOK["limits"][k] for k in rb["limits"])
    assert L.record_solved("cell_heating", {"heat_resid": 0.1}) is None   # proposed once only
    assert DEFAULT_RULEBOOK["version"] == 1                                # base not mutated


# ---------------- route ----------------
ST = [{"id": "S1", "lat": 12.98, "lon": 77.60, "online": False}, {"id": "S2", "lat": 13.05, "lon": 77.65, "online": True},
      {"id": "S3", "lat": 14.5, "lon": 78.5, "online": True}]


def test_route_skips_offline_and_picks_nearest_reachable():
    p = route.plan([12.97, 77.59], 0.6, 6.0, 0.7, ST)
    assert p["ok"] and p["choice"]["station"] == "S2"


def test_route_no_reachable_station_gives_safe_advice():
    p = route.plan([12.97, 77.59], 0.01, 6.0, 0.4, ST)
    assert not p["ok"] and "assistance" in p["advice"]
    assert route.plan(None, 0.5, 6, 1, ST)["ok"] is False


# ---------------- ota: issuer guards ----------------
def test_issuer_signs_verifiable_monotonic_commands():
    i = Issuer(PRIV)
    a, b = i.issue("V1", "derate", {"limit": 0.7}), i.issue("V1", "derate", {"limit": 0.6})
    assert crypto.verify(a, PUB) and crypto.verify(b, PUB) and b["counter"] == a["counter"] + 1
    assert i.issue("V2", "derate", {"limit": 0.7})["counter"] == 1          # per-vehicle counters
    bad = dict(a); bad["params"] = {"limit": 1.0}
    assert not crypto.verify(bad, PUB)


@pytest.mark.parametrize("kind,params,kw,msg", [
    ("derate", {"limit": 0.1}, {}, "guard"), ("derate", {"limit": 1.5}, {}, "guard"), ("limp", {}, {}, "guard"),
    ("nuke", {}, {}, "unknown"), ("behavioural", {"mode": "eco"}, {}, "consent"),
    ("security_patch", {}, {"consent": {"decision": "approved"}}, "OEM"),
    ("behavioural", {}, {"consent": {"decision": "denied"}}, "consent")])
def test_issuer_refuses(kind, params, kw, msg):
    with pytest.raises(Refused, match=msg): Issuer(PRIV).issue("V1", kind, params, **kw)


def test_consent_and_oem_proofs_bound_to_counter():
    c = Issuer(PRIV).issue("V1", "security_patch", {"id": 1}, consent={"decision": "approved"}, oem={"approved": True})
    assert c["consent"]["counter"] == c["counter"] == c["oem_approval"]["counter"] and c["consent"]["vehicle_id"] == "V1"


# ---------------- ota service ----------------
def test_derate_issued_without_consent_when_twin_recommends():
    o = OtaService(PRIV)
    out = o.process("cloud.twin", {"vehicle_id": "V1", "final_cause": "pump_fault", "recommended_cap": 0.6, "edge_actions": ["alert"], "incident_id": "i"})
    cmds = [m for t, m, _ in out if t == "commands.out"]
    assert len(cmds) == 1 and cmds[0]["kind"] == "derate" and cmds[0]["params"]["limit"] == 0.6
    assert any(t == "notify.out" for t, _, _ in out)


def test_edge_already_derated_means_no_duplicate_command():
    out = OtaService(PRIV).process("cloud.twin", {"vehicle_id": "V1", "final_cause": "pump_fault", "recommended_cap": 0.6,
                                                    "edge_actions": ["derate=0.6"], "incident_id": "i"})
    assert not [1 for t, _, _ in out if t == "commands.out"]


def test_security_incident_notifies_only():
    out = OtaService(PRIV).process("cloud.twin", {"vehicle_id": "V1", "security": True, "edge_cause": "can_attack:flood", "incident_id": "i"})
    assert [t for t, _, _ in out] == ["notify.out"] and out[0][1]["channel"] == "security"


def test_consent_flow_behavioural_command_only_after_approval():
    o = OtaService(PRIV)
    out = o.process("cloud.twin", {"vehicle_id": "V1", "final_cause": "efficiency_degradation", "recommended_cap": 1.0, "edge_actions": []})
    rid = next(m["request_id"] for t, m, _ in out if t == "notify.out" and m.get("request_id"))
    assert not [1 for t, _, _ in out if t == "commands.out"]
    denied = OtaService(PRIV)
    r = denied.process("cloud.twin", {"vehicle_id": "V1", "final_cause": "efficiency_degradation", "recommended_cap": 1.0, "edge_actions": []})
    rid2 = next(m["request_id"] for t, m, _ in r if t == "notify.out" and m.get("request_id"))
    assert not [1 for t, _, _ in denied.process("cloud.ota", {"kind": "consent_decision", "request_id": rid2, "decision": "denied"}) if t == "commands.out"]
    ok = o.process("cloud.ota", {"kind": "consent_decision", "request_id": rid, "decision": "approved"})
    cmd = [m for t, m, _ in ok if t == "commands.out"][0]
    assert cmd["kind"] == "behavioural" and cmd["consent"]["counter"] == cmd["counter"]
    assert o.process("cloud.ota", {"kind": "consent_decision", "request_id": rid, "decision": "approved"})[0][0] == "notify.out"   # replayed approval refused


def test_security_patch_waits_for_oem_even_with_consent():
    o = OtaService(PRIV)
    o.pending["r1"] = {"vehicle_id": "V1", "kind": "security_patch", "params": {}, "consent": None, "oem": None}
    assert o.process("cloud.ota", {"kind": "consent_decision", "request_id": "r1", "decision": "approved"}) == []
    out = o.process("cloud.ota", {"kind": "oem_approval", "request_id": "r1", "approved": True})
    assert out and out[0][1]["kind"] == "security_patch"


# ---------------- rollout ----------------
def rb2():
    rb = dict(DEFAULT_RULEBOOK); rb["version"] = 2; return rb


def run_stage(ro, ok_fn):
    cmds = ro.advance()
    for c in cmds: ro.on_result(c["vehicle_id"], *ok_fn(c))
    return cmds


def test_rollout_stages_5_25_100_then_complete():
    vs = [f"V{i:02d}" for i in range(40)]
    ro = Rollout("r", rb2(), vs, vs, Issuer(PRIV))
    sizes = [len(run_stage(ro, lambda c: (True, "ok"))) for _ in range(3)]
    assert sizes == [2, 8, 30]                                  # cumulative 2, 10, 40
    ro.advance(); assert ro.status == "complete" and ro.snapshot()["applied"] == 40


def test_rollout_does_not_advance_until_stage_reports():
    vs = [f"V{i}" for i in range(20)]
    ro = Rollout("r", rb2(), vs, vs, Issuer(PRIV))
    ro.advance()
    assert ro.advance() == [] and ro.stage == 0


def test_rollout_halts_and_rolls_back_on_failures():
    vs = [f"V{i:02d}" for i in range(40)]
    ro = Rollout("r", rb2(), vs, vs, Issuer(PRIV), halt_fail=0.2)
    run_stage(ro, lambda c: (True, "ok"))
    cmds = ro.advance()
    for n, c in enumerate(cmds): ro.on_result(c["vehicle_id"], n >= 3, "rejected")      # 3 of 8 fail -> 27%+ overall
    back = ro.advance()
    assert ro.status == "halted" and back and all(c["kind"] == "rollback" for c in back)
    assert ro.advance() == []                                                           # stays halted


def test_rollout_skips_vehicles_without_consent():
    vs = [f"V{i}" for i in range(10)]
    ro = Rollout("r", rb2(), vs, vs[1:], Issuer(PRIV))
    assert "V0" not in [c["vehicle_id"] for c in ro.advance()] and ro.snapshot()["skipped_no_consent"] >= 1


def test_ota_service_rollout_auto_advances_on_results():
    o = OtaService(PRIV)
    for i in range(20): o.process("cloud.fleet", {"kind": "summary", "vehicle_id": f"V{i:02d}"})
    out = o.process("cloud.ota", {"kind": "rulebook_approve", "rulebook": rb2()})
    sent = [m for t, m, _ in out if t == "commands.out"]
    assert len(sent) == 1 and sent[0]["kind"] == "rulebook_update"            # 5% of 20
    res = o.process("cloud.ota", {"kind": "command_result", "vehicle_id": sent[0]["vehicle_id"], "ok": True, "why": "ok"})
    assert len([1 for t, _, _ in res if t == "commands.out"]) >= 4           # next stage issued


# ---------------- pipeline over MemBus ----------------
def test_pipeline_escalation_to_signed_derate_and_route(monkeypatch):
    monkeypatch.setenv("TOPIC_PREFIX", "quantara_")
    from quantara_core import config
    bus, T = MemBus(), config.topic
    rca, tw, rt, ota = RcaService(), TwinService(), RouteService(), OtaService(PRIV)
    bus.publish(T("cloud.fleet"), {"kind": "feeds", "grid": {"stations": ST}})
    ring = make_ring(extra=3.0, flow=3.0, P=60.0, T0=44.0, n=30)
    bus.publish(T("cloud.escalations"), esc(ring=ring, cause="unknown", ev={"flow_ratio": 0.25, "heat_resid": 0.1, "power_frac": 0.7}), key="V1")
    pump = lambda svc, grp, ins: [bus.publish(T(ot), om, key=k) for t, _, m in bus.poll(grp, [T(i) for i in ins], 100)
                                  for ot, om, k in svc.process(t[len(T("")):], m)]
    pump(rca, "g-rca", ["cloud.escalations", "cloud.security"])
    pump(tw, "g-tw", ["cloud.rca"])
    pump(rt, "g-rt", ["cloud.fleet", "cloud.twin"])
    pump(ota, "g-ota", ["cloud.twin"])
    cmds = [m for _, m in bus.log[T("commands.out")]]
    assert cmds and cmds[0]["kind"] == "derate" and crypto.verify(cmds[0], PUB) and cmds[0]["params"]["limit"] <= 0.7
    plan = bus.log[T("cloud.route")][0][1]
    assert plan["vehicle_id"] == "V1" and (plan.get("choice") or plan.get("nearest"))
    assert bus.log[T("cloud.twin")][0][1]["twin"]["ok"]
