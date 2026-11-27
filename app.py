"""Condense transform entrypoint. ROLE=rca|twin|route|ota (same image, four deployments)."""
import logging
import sys
import time

from quantara_core import config, topics
from quantara_core.bus import get_bus
from svc.ota import OtaService
from svc.services import RcaService, RouteService, TwinService

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("svc")
ROLES = {"rca": (RcaService, ["cloud.escalations", "cloud.security", "cloud.ota", "cloud.twin"]),
         "twin": (TwinService, ["cloud.rca"]),
         "route": (RouteService, ["cloud.twin", "cloud.fleet"]),
         "ota": (OtaService, ["cloud.twin", "cloud.ota", "cloud.fleet"])}


def build(role):
    if role == "ota":
        return OtaService(config.env("SIGNING_KEY", required=True))
    return ROLES[role][0]()


def main():
    role = config.env("ROLE", required=True)
    stage, bus, T = build(role), get_bus(), config.topic
    ins = ROLES[role][1]
    log.info("topics: %s", {k: v for k, v in topics.ensure_topics().items() if v != "exists"} or "all exist")
    log.info("starting role=%s prefix=%s in=%s", role, config.prefix(), ins)
    grp, n, last = config.group(f"svc-{role}"), 0, time.time()
    while True:
        try:
            for t, _, m in bus.poll(grp, [T(i) for i in ins], max_n=200, timeout=0.5):
                for ot, om, key in stage.process(t[len(T("")):], m):
                    bus.publish(T(ot), om, key=key); n += 1
            if time.time() - last >= 30:
                last = time.time()
                log.info("out=%d stats=%s bus_ok=%s bus_failed=%s", n, getattr(stage, "stats", {}),
                         getattr(bus, "ok", "-"), getattr(bus, "failed", "-"))
        except Exception:
            log.exception("loop error (continuing)"); time.sleep(1)


if __name__ == "__main__":
    main()
