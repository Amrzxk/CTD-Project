# H-IDS Backend — Class Diagram

A class-level model of the FastAPI backend (`app/`). It covers the four
sub-systems that make up the server side:

1. **Persistence** — SQLAlchemy ORM models + repository modules (Postgres).
2. **ML inference & enrichment** — the model managers, the feature
   standardizer, and the MITRE mapper.
3. **Live capture & session control plane** — the session registry, the
   per-session loggers, the hybrid correlation buffer, and the standalone
   workers / replay coroutines.
4. **Auth, schemas & app wiring** — security primitives, FastAPI
   dependencies, Pydantic request/response models, and the routers.

> True OOP classes are shown with full attributes/methods. Python modules
> that are collections of functions (workers, repositories, auth helpers,
> routers) are shown with the **«module»** / **«router»** stereotype and
> their key callables, because they are first-class architectural units even
> though they aren't `class` definitions.

---

## 1. Overview — sub-system dependencies

```mermaid
flowchart LR
    subgraph API["API layer (app/api)"]
        routes["«router» routes.py"]
        live["«router» live.py"]
        authR["«router» auth.py"]
        admin["«router» admin.py"]
        mitreR["«router» mitre.py"]
    end

    subgraph CORE["Core (app/core)"]
        HMM["HierarchicalModelManager"]
        MM["ModelManager"]
        DS["DataStandardizer"]
        MITRE["MitreMapper"]
        REG["LiveSessionRegistry"]
        SESS["LiveSession"]
        SLOG["SessionLogger"]
        PEND["_Pending"]
        FMW["«module» flow_meter_worker"]
        STW["«module» snort_tailer_worker"]
        SOFF["«module» snort_offline"]
        REPLAY["«module» pcap_replay"]
        PERS["«module» live_persister"]
    end

    subgraph DB["Persistence (app/db)"]
        ORM["ORM models\nUser · Prediction\nAckHistory · Suppression\nUserAdminHistory"]
        REPO["«module» repositories\npredictions · users\nack_history · suppressions"]
        ENG["engine · SessionLocal\nget_session"]
    end

    subgraph AUTH["Auth (app/auth)"]
        SEC["«module» security"]
        DEP["«module» dependencies"]
    end

    REDIS[("Redis\nflow hashes · pub/sub")]
    PG[("Postgres 16")]

    routes --> DS & HMM & MITRE & REPO & SOFF
    live --> REG & DS & HMM & MITRE & PEND & REDIS
    authR --> SEC & DEP & REPO
    admin --> DEP & REPO
    mitreR --> MITRE
    REG --> SESS --> SLOG
    REG --> PERS
    PERS --> PEND & REPO & DS & HMM & MITRE & REDIS
    REPLAY --> FMW & SOFF & REDIS
    FMW --> REDIS
    STW --> REDIS
    HMM --|> MM
    REPO --> ORM
    ORM --> ENG --> PG
    DEP --> SEC & REPO
```

---

## 2. ML inference & enrichment

```mermaid
classDiagram
    direction LR

    class ModelManager {
        +model: LGBMClassifier
        +selected_features: list~str~
        +class_labels: list~str~
        +scaler: StandardScaler
        +model_version: str
        +predict(df) list~dict~
    }

    class HierarchicalModelManager {
        +REQUIRED_FILES: tuple
        +models_dir: Path
        +selected_features: list~str~
        +class_labels: list~str~
        +s1: lgb.Booster
        +tau1: float
        +scaler_S1
        +s2: CatBoostClassifier
        +family_classes: list~str~
        +scaler_S2
        +s3_models: dict~str,XGBClassifier~
        +s3_classes: dict~str,list~
        +scalers_S3: dict
        +manifest: dict
        +model_version: str
        +predict(df) list~dict~
    }

    class DataStandardizer {
        +selected_features: list~str~
        -_REDIS_TO_CIC: dict
        -_CIC_TO_REDIS: dict
        +from_redis_flow(flow_hash) DataFrame
        +from_records(records) DataFrame
        +from_csv(path) DataFrame
        +from_excel(path) DataFrame
        +from_pcap(path, cb) DataFrame
        -_map_nfstream_to_cic(df)
        -_process(df)
        -_clean(df)
    }

    class MitreMapper {
        -_version: str
        -_framework: str
        -_min_confidence: float
        -_bands: dict
        -_mappings: dict
        -_unmapped_seen: set
        +min_confidence: float
        +categories: list~str~
        +lookup(category) dict
        +get_matrix() dict
        +enrich_prediction(pred) dict
        -_resolve_band(conf) str
    }

    ModelManager <|-- HierarchicalModelManager : same predict() contract
    DataStandardizer ..> HierarchicalModelManager : feeds 70-feature DataFrame
    MitreMapper ..> DataStandardizer : enriches predictions
```

`ModelManager` and `HierarchicalModelManager` are **interchangeable** — they
share the `predict(df) -> list[dict]` contract, so `main.py` picks one at
startup (hierarchical when the four sentinels are on disk, legacy otherwise)
and the routes never care which is loaded.

---

## 3. Persistence — ORM models & repositories

```mermaid
classDiagram
    direction TB

    class Base {
        <<DeclarativeBase>>
        +metadata: MetaData
    }

    class User {
        +id: int
        +username: str
        +password_hash: str
        +role: str
        +is_active: bool
        +must_change_password: bool
        +token_version: int
        +created_at: datetime
        +last_login_at: datetime
    }

    class Prediction {
        +id: str
        +flow_timestamp: datetime
        +first_seen_at: datetime
        +source_ip: str
        +destination_ip: str
        +source_port: int
        +destination_port: int
        +protocol: str
        +prediction: str
        +attack_type: str
        +family: str
        +subtype: str
        +confidence: float
        +severity: str
        +stage1_p: float
        +stage2_p: float
        +stage3_p: float
        +stage2_probs: JSONB
        +stage3_probs: JSONB
        +ml_features: JSONB
        +mitre: JSONB
        +source: str
        +model_version: str
        +snort_msg: str
        +snort_sid: int
        +snort_classtype: str
        +snort_priority: int
        +ack_state: str
        +ack_at: datetime
        +ack_note: str
        +ack_by: int
    }

    class AckHistory {
        +id: int
        +prediction_id: str
        +user_id: int
        +from_state: str
        +to_state: str
        +note: str
        +changed_at: datetime
    }

    class Suppression {
        +id: str
        +kind: str
        +value: str
        +expires_at: datetime
        +note: str
        +hits: int
        +created_at: datetime
        +created_by: int
    }

    class UserAdminHistory {
        +id: int
        +actor_id: int
        +target_id: int
        +target_username: str
        +action: str
        +created_at: datetime
    }

    Base <|-- User
    Base <|-- Prediction
    Base <|-- AckHistory
    Base <|-- Suppression
    Base <|-- UserAdminHistory

    AckHistory "*" --> "1" Prediction : FK prediction_id (CASCADE)
    AckHistory "*" --> "0..1" User : FK user_id (SET NULL)
    Prediction "*" --> "0..1" User : FK ack_by (SET NULL)
    Suppression "*" --> "0..1" User : FK created_by (SET NULL)
    UserAdminHistory "*" --> "0..1" User : FK actor_id / target_id
```

### Repository modules (thin async functions over the ORM)

```mermaid
classDiagram
    direction LR

    class predictions_repo {
        <<module>>
        +to_full_dict(p) dict
        +to_summary_dict(p) dict
        +live_event_to_insert_dict(event) dict
        +insert_many(session, rows) int
        +insert_from_live_events(...) 
        +get(session, id) Prediction
        +list_page(...) 
        +counts_by_ack_state(session) dict
        +ack(...) 
        +bulk_ack(...) 
        +ack_by_match(...) 
        +analytics_aggregates(...) 
        +delete_older_than(session, days) int
        +enforce_hard_cap(session, cap) int
    }

    class users_repo {
        <<module>>
        +get_by_username(session, name) User
        +get_by_id(session, id) User
        +create(...) User
        +update_last_login(session, id)
        +has_any(session) bool
        +list_all(session) list~User~
        +set_active(...) 
        +reset_password(...) 
    }

    class ack_history_repo {
        <<module>>
        +record(...) AckHistory
        +list_for(session, pred_id) list
    }

    class suppressions_repo {
        <<module>>
        +list_active(session) list
        +add(...) Suppression
        +remove(session, id) bool
        +match(session, prediction) Suppression
        +filter_predictions(session, batch) tuple
        +to_dict(rule) dict
    }

    class user_admin_history_repo {
        <<module>>
        +record(...) 
        +list_recent(...) 
    }

    class db {
        <<module>>
        +engine: AsyncEngine
        +SessionLocal: async_sessionmaker
        +get_session() AsyncIterator~AsyncSession~
    }

    class retention {
        <<module>>
        +start() asyncio.Task
        -_run_once()
        -_loop()
        -_purge_session_logs(dir, days) int
    }

    predictions_repo ..> Prediction
    predictions_repo ..> AckHistory
    users_repo ..> User
    ack_history_repo ..> AckHistory
    suppressions_repo ..> Suppression
    user_admin_history_repo ..> UserAdminHistory
    predictions_repo ..> db : AsyncSession
    retention ..> predictions_repo
```

---

## 4. Live capture & session control plane

```mermaid
classDiagram
    direction TB

    class LiveSession {
        <<dataclass>>
        +id: str
        +source: interface|pcap
        +detection_mode: ml|snort|hybrid
        +started_at: datetime
        +owner_user_id: int
        +pcap_path: str
        +pcap_speed: float
        +pcap_attached: bool
        +persist_to_alerts: bool
        +logger: SessionLogger
        +replay_task: asyncio.Task
        +persister_task: asyncio.Task
        +stop_event: asyncio.Event
        +to_public_dict() dict
        +to_redis_dict() dict
    }

    class LiveSessionRegistry {
        -_redis: aioredis.Redis
        -_log_dir: Path
        -_current: LiveSession
        -_lock: asyncio.Lock
        +model_manager
        +data_standardizer
        +mitre_mapper
        +model_version: str
        +current() LiveSession
        +current_from_redis() dict
        +start(source, mode, owner, speed) LiveSession
        +attach_pcap(id, path, task)
        +stop(id) bool
        +clear_stale_redis_state() bool
        +shutdown()
        -_stop_locked(reason)
        -_publish_redis_state(s)
        -_publish_event(evt, id)
    }

    class SessionLogger {
        -_log_dir: Path
        -_session_id: str
        -_csv_path: Path
        -_ndjson_path: Path
        -_csv_writer: DictWriter
        -_row_count: int
        -_closed: bool
        +start()
        +log(event)
        +close()
        +session_id: str
        +row_count: int
        +csv_path: Path
        +ndjson_path: Path
    }

    class _Pending {
        -_data: dict
        -_flow_ttl: float
        -_snort_ttl: float
        +add_flow(key, ts) dict
        +add_snort(key, snort, ts) bool
        +reap(now) list
        +drain() list
        +pop(key)
    }

    class TrafficLogger {
        -_log_dir: Path
        -_current_file: Path
        -_writer: DictWriter
        -_row_count: int
        +start_session()
        +log(packet)
        +close()
        +get_log_files() list
    }

    LiveSessionRegistry "1" o-- "0..1" LiveSession : holds single slot
    LiveSession "1" *-- "1" SessionLogger : owns CSV+NDJSON
    LiveSession "1" *-- "1" asyncio.Event : stop_event
    LiveSessionRegistry ..> live_persister : spawns persister_task
    live_persister ..> _Pending : hybrid correlation buffer
```

### Standalone workers, replay & persister (procedural modules)

```mermaid
classDiagram
    direction LR

    class flow_meter_worker {
        <<module · process>>
        +run()
        +extract_cic_features(flow) dict
        -_store_flow(r, key, features)
        -_connect_redis() Redis
        FLOW_COMPLETED_CHANNEL
    }

    class snort_tailer_worker {
        <<module · process>>
        +run()
        -_tail_lines(path) Generator
        -_parse_alert(line) dict
        PUBSUB_CHANNEL = snort_alerts
    }

    class snort_offline {
        <<module>>
        +is_available() bool
        +run(pcap_path) dict~key,alert~
        -_parse_alert_line(line) dict
        -_to_wsl_path(p) str
    }

    class pcap_replay {
        <<module>>
        +replay_pcap(path, speed, mode, id, redis, stop_event)
        -_iter_flows_sync(path) list
        -_flow_key_for(flow, features) str
    }

    class live_persister {
        <<module>>
        +run_persister(session, redis, model_mgr, ds, mitre, ver)
    }

    class key_utils {
        <<module>>
        +flow_key(src_ip, dst_ip, src_port, dst_port, proto) str
    }

    flow_meter_worker ..> key_utils
    snort_tailer_worker ..> key_utils
    snort_offline ..> key_utils
    pcap_replay ..> flow_meter_worker : reuses extract_cic_features
    pcap_replay ..> snort_offline
    live_persister ..> _Pending
    live_persister ..> predictions_repo
    live_persister ..> suppressions_repo
    live_persister ..> DataStandardizer
    live_persister ..> MitreMapper
```

---

## 5. Auth, API schemas & routers

```mermaid
classDiagram
    direction TB

    class security {
        <<module>>
        +SESSION_COOKIE_NAME
        +hash_password(plain) str
        +verify_password(plain, hash) bool
        +needs_rehash(hash) bool
        +create_session_token(user_id, role, ...) str
        +decode_session_token(token) dict
        +revocation_ttl_seconds(claims) int
    }

    class dependencies {
        <<module>>
        +get_current_user(request, cookie, session) User
        +require_admin(user) User
        -_jti_is_revoked(request, jti) bool
    }

    class LoginRequest { <<pydantic>> +username +password }
    class ChangePasswordRequest { <<pydantic>> +old_password +new_password }
    class CreateUserRequest { <<pydantic>> +username +password }
    class ResetPasswordRequest { <<pydantic>> +password }
    class SetActiveRequest { <<pydantic>> +is_active }
    class UserOut { <<pydantic>> +id +username +role +is_active }

    class AckRequest { <<pydantic>> +state +note }
    class BulkAckRequest { <<pydantic>> +ids +state +note }
    class SuppressionRequest { <<pydantic>> +kind +value +expires_at }
    class ManualFlowInput { <<pydantic>> +proto +sport +dsport +sbytes +... }
    class StartSessionRequest { <<pydantic>> +source +detection_mode +speed +persist_to_alerts }
    class LiveSessionOut { <<pydantic>> +session_id +source +detection_mode +row_count }

    dependencies ..> security : decode_session_token
    dependencies ..> users_repo : get_by_id
    dependencies ..> User
```

### Routers (FastAPI `APIRouter` modules)

```mermaid
classDiagram
    direction LR

    class routes {
        <<router>>
        GET /predictions
        GET /predictions/{id}
        POST /predictions/{id}/ack
        POST /predictions/ack/bulk
        POST /predictions/ack/by-match
        GET /analytics
        POST /analyze/upload
        POST /analyze/upload/stream
        POST /analyze/manual
        GET·POST /suppressions
    }
    class live {
        <<router>>
        GET /live/stream (SSE)
        GET·POST·DELETE /live/session
        POST /live/session/{id}/pcap
        GET /live/session/{id}/log
        -_sse_generator()
        -_build_event()
        -_run_ml()
        -_apply_mode_filter()
    }
    class auth_router {
        <<router>>
        POST /auth/login
        POST /auth/logout
        GET /auth/me
        POST /auth/change-password
    }
    class admin_router {
        <<router>>
        GET·POST /admin/users
        POST /admin/users/{id}/reset-password
        POST /admin/users/{id}/active
    }
    class mitre_router {
        <<router>>
        GET /mitre/matrix
        GET /mitre/lookup/{category}
    }

    routes ..> predictions_repo
    routes ..> suppressions_repo
    routes ..> DataStandardizer
    routes ..> HierarchicalModelManager
    routes ..> MitreMapper
    routes ..> snort_offline
    live ..> LiveSessionRegistry
    live ..> _Pending
    live ..> DataStandardizer
    live ..> HierarchicalModelManager
    auth_router ..> security
    auth_router ..> users_repo
    admin_router ..> dependencies
    admin_router ..> users_repo
    mitre_router ..> MitreMapper
```

---

## 6. Key relationship notes

| Relationship | Meaning |
|---|---|
| `HierarchicalModelManager --|> ModelManager` | Not literal inheritance — they share the `predict(df)` **contract**; startup swaps one for the other via `MODEL_MODE`. |
| `LiveSessionRegistry o-- LiveSession` | Single-slot aggregation — at most **one** session system-wide; starting a new one auto-stops the old. |
| `LiveSession *-- SessionLogger` | Composition — the logger's CSV/NDJSON lifecycle is bound to the session's. |
| `live_persister ..> _Pending` | The persister and the SSE generator each hold their **own** `_Pending` buffer to do identical flow↔Snort hybrid correlation. |
| `pcap_replay ..> flow_meter_worker` | Replay reuses `extract_cic_features()` so PCAP and live-interface paths produce identical features. |
| `AckHistory --> Prediction (CASCADE)` | Deleting a prediction cascades its audit rows; user FKs are `SET NULL` so the trail survives user deletion. |
| Redis pub/sub | `flow_meter_worker`/`pcap_replay` PUBLISH `flow_completed`; `snort_tailer_worker`/`snort_offline` feed `snort_alerts`; `live.py` + `live_persister` SUBSCRIBE both. |

All shared runtime singletons (`model_manager`, `data_standardizer`,
`mitre_mapper`, `live_sessions` registry, `redis_pool`, `traffic_logger`)
are constructed in `app/main.py`'s lifespan and hung off `app.state`, then
injected into routes via `Request.app.state`.
