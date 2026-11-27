# quantara-services

Repo 3 of 4 (ingest · stream · **services** · ops) for Configure 2026. Synthetic data only.
One image, four Condense Transform deployments selected by `ROLE`:

| ROLE | consumes | produces | what it does |
|---|---|---|---|
| `rca` | `cloud.escalations`, `cloud.security`, `cloud.ota`, `cloud.twin` | `cloud.rca`, `cloud.fleet`, `cloud.ota` | posterior = likelihood × learned prior; fleet correlation; learning loop (technician feedback → priors; recurring twin-confirmed causes → *proposed* rulebook change) |
| `twin` | `cloud.rca` | `cloud.twin` | thermal digital twin (sub-steps ≤ 5 model-s): replays the freeze frame, fits hidden heat, projects time-to-derate under 100/70/40 % power, recommends least restrictive safe cap |
| `route` | `cloud.twin`, `cloud.fleet` | `cloud.route` | reachable online charging station given SoC, efficiency and derate |
| `ota` | `cloud.twin`, `cloud.ota`, `cloud.fleet` | `commands.out`, `notify.out`, `cloud.ota` | Ed25519-signed commands (per-vehicle counter, expiry, vehicle id, guards), consent + OEM approvals bound to the counter, staged rollouts 5/25/100 % with halt and rollback |

Human inputs arrive on `cloud.ota`: `feedback`, `consent_decision`, `oem_approval`, `rulebook_approve`, `rollout_tick`.
Env: `TOPIC_PREFIX`, `KAFKA_*` (5), `ROLE`, and for `ota` a `SIGNING_KEY` (Password; base64 Ed25519 private key).
Test: `pip install -r requirements.txt pytest && pytest`. MIT. Built with AI assistance (Claude Code).
Simulated: the vehicles, station list and owner/OEM approvals; route distances are straight-line × 1.3 detour factor.
