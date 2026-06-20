# AI-Based Network Monitoring and Anomaly Detection System

An enterprise-grade, AI-powered network monitoring and anomaly detection system developed for Hewlett Packard Enterprise. The system simulates a modern Security Operations Center (SOC) architecture and provides real-time network threat visualization through an interactive 3D WebGL interface, comprehensive security dashboard, and admin console with human-in-the-loop credential rotation workflow.

## Overview

The system ingests raw network traffic, extracts behavioral features, executes high-speed machine learning inference in a microservice architecture, and triggers automated orchestrated responses (including HashiCorp Vault credential rotation) when malicious patterns are detected.

### Core Features

- **AI-Powered Threat Detection:** XGBoost + LightGBM ensemble model with 97.3% accuracy
- **Real-Time Visualization:** 3D globe with live attack arcs, 10-stage pipeline animation
- **Human-in-the-Loop Security:** Admin approval workflow for high-severity threats
- **Automated Credential Rotation:** HashiCorp Vault integration with configurable rotation modes
- **Multi-Pod Scalability:** Redis-based WebSocket broadcasting for Kubernetes deployments
- **Complete Audit Trail:** Append-only PostgreSQL audit log with admin attribution
- **Infrastructure Security:** Dynamic database credentials, AppRole authentication, JWT-based admin access

## The Pipeline Architecture
The dashboard visually maps and documents an enterprise-grade 10-stage pipeline. Here is exactly what happens during a real-time event:

* **Network / Apps:** We continuously monitor network traffic across the enterprise. Raw data packets (PCAP) from routers and application logs are collected and converted into a standard format, providing the foundational telemetry stream for our security pipeline.
* **Zeek / Suricata (IDS):** Traffic passes through an Intrusion Detection System (IDS). Tools like Suricata and Zeek perform Deep Packet Inspection (DPI) to quickly scan for known malicious patterns and extract useful network metadata (like HTTP or DNS info).
* **Elastic Beats:** To keep data organized, we use log shippers like Filebeat. They collect raw logs from the IDS, clean them up into a standardized format called the Elastic Common Schema (ECS), and map IP addresses to geographic locations.
* **Apache Kafka:** To transport this massive amount of data smoothly, we use Apache Kafka as a high-throughput event streaming broker. It acts as an immutable buffer, ensuring our AI Engine isn't overwhelmed during sudden spikes in network traffic.
* **AI Detection Engine:** The core brain of the system. Our FastAPI microservice consumes the Kafka stream and engineers complex behavioral features in split-seconds. It relies on a state-of-the-art AI ensemble (XGBoost, LightGBM, Random Forest, Gradient Boosting) to predict if an event is a novel, previously unseen threat.
* **SOAR:** If the AI flags a threat, our SOAR (Security Orchestration, Automation, and Response) platform takes over. Rather than waiting for a human analyst, it automatically triggers conditional incident response playbooks—like isolating machines or initiating automated password resets.
* **HashiCorp Vault (Human-in-the-Loop):** For BLOCK/CRITICAL threats, the system creates a pending admin alert instead of auto-rotating credentials. The admin must review the forensic data, model scores, and pipeline results before approving the rotation.
* **Credential Rotation:** Once approved by an admin, Vault executes a secure credential rotation. It instantly invalidates old, hijacked sessions and generates cryptographically secure, brand-new passwords and API keys for our databases and services.
* **Credential Distribution:** Once new passwords are created, they must be distributed safely. The system automatically pushes these new Vault secrets back to our servers and active microservices using encrypted TLS tunnels, restoring security without taking the system offline.
* **ELK / Grafana:** Finally, every single event—safe traffic or neutralized threat—is permanently recorded. We index all data into an Elasticsearch database, allowing human analysts to search audit logs and view real-time visualizations on Kibana dashboards.

## Security Admin Console
The admin dashboard provides:

* **Real-time Alert Queue** — Critical and high-severity threats appear as pending alerts
* **Forensic Detail View** — Full event facts, model scores (XGBoost, LightGBM, Ensemble), geo data, and all 10 pipeline stage results
* **Approve / Reject Workflow** — One-click credential rotation approval or false positive rejection
* **Audit Log** — Complete, append-only history of all admin actions with timestamps, admin attribution, and notes
* **WebSocket Notifications** — Instant toast alerts when new critical threats are detected
* **User Registration Management** — Approve or reject pending access requests from the public portal. Approval fully provisions the user (Vault secret, department-based role, and a known home region inherited from department peers) and emails the issued credentials
* **Pipeline Reset (Danger Zone)** — Two-step confirmed reset with one-time token (60s TTL); preserves audit log and Kafka topics

### Admin Authentication & Security

The admin console is secured with **JWT-based authentication** and comprehensive audit logging:

* **JWT Authentication** — Admins authenticate with Security department credentials; all API requests validated via `Bearer` token
* **Vault-Stored Signing Key** — JWT signing secret stored in HashiCorp Vault (`hpe/admin-jwt`), never hardcoded
* **Short-Lived Tokens** — 30-minute TTL prevents session hijacking
* **Admin Attribution** — Every action logged with admin username for full traceability and non-repudiation
* **Append-Only Audit Trail** — `hpe_admin_audit_log` table never truncated, even during resets
* **Safer Pipeline Reset** — Two-step reset with 60-second confirmation token; preserves audit log and Kafka topics

## Threat Simulation Portal & Department Portals
The Enterprise Login Portal (`http://localhost:8080`) is a full interactive security simulation sandbox built to feel like a real enterprise intranet:

* **Dynamic Startup Seeding:** At backend startup, the pipeline dynamically syncs and seeds 200 users (from `user_profiles.json`) into HashiCorp Vault KV storage and the PostgreSQL `hpe_users` database.
* **Demo Credential Helper (curated):** The login-page dropdown lists all active users, but **only 3 curated demo accounts** (`USR-0001` Developer, `USR-0002` Finance, `USR-0005` Admin, marked with ★) reveal their password and allow autofill. All other accounts are masked (`••••••••`) — full credentials are emailed to the admin at Vault initialization. The helper has request timeouts + auto-retry so it never hangs on a slow tunnel.
* **Department-Themed Portals:** Upon authorization, the workspace renders a department-branded intranet — distinct accent color, time-aware hero greeting, department KPIs, quick-app shortcuts, and an announcements feed — tailored to the user's role:
  * **Developer (Engineering):** Repository access, build/CI status, PRs, deploys.
  * **Finance:** Corporate ledgers, sensitive document downloads, invoice/budget KPIs.
  * **HR:** Employee directory, headcount/onboarding KPIs.
  * **Sales:** Client CRM, pipeline/quota KPIs.
  * **Admin (Security):** Infrastructure status and security/rotation controls.
* **Active Password HUD:** Displays the current session password (synced from Vault) with a one-click copy button.
* **Session Persistence:** A page reload re-hydrates the session and keeps you in your workspace instead of bouncing back to the login screen.

### Login Memory & Anomaly Simulation
The portal tracks per-user login memory in PostgreSQL (`last_login_region`, `last_login_ip`, and a rolling `last_failed_attempt`):

* **User-Selected Region:** The Access Region is chosen in the Security Center (not detected by IP). Selecting a region different from the previous login fires an **Impossible Travel** popup, and the backend auto-flags impossible travel when the region changes within a 6-hour window.
* **Real Failed-Attempt Count:** The panel shows the *actual* recorded wrong-password count (windowed to 5 minutes), not a manual slider.
* **Other Simulations:** VPN/proxy usage, geographic mismatch, off-hours access, and data exfiltration via large file downloads (with an abnormal-download warning modal).
* **Clean Baseline on Login:** Each login starts from the user's home region with failed attempts cleared, so stale anomaly state never leaks across sessions.

### Automated Credential Rotation & Session Management

The system implements intelligent credential rotation with multiple triggers:

**Rotation Triggers:**
1. **Threat Detection** — BLOCK/CRITICAL threats trigger rotation (mode-dependent: automatic in production, admin-approved in demo)
2. **Brute-Force Detection** — Successful login after 5+ failed attempts within 5 minutes triggers immediate rotation
3. **VPN Anomalies** — Geographic mismatch via commercial VPN creates alert requiring review
4. **Admin Manual** — Security team can trigger rotation from admin console

**Session Watchers:**
- Portal detects credential rotation within seconds
- Workspace locks with **⚡ Credentials Rotated** notification showing new password
- User must re-authenticate with rotated credentials
- Login memory resets to clean baseline on each rotation

**Email Notifications:**
- Vault initialization sends complete credential table to admin
- Individual rotation events send new password to security team
- VPN login detections trigger immediate alerts with geolocation data

### New User Registration Workflow

**Registration Process:**
1. User submits registration request with username and department selection
2. Account created in `pending` status — login blocked until approval
3. Request appears in admin console with VPN detection if applicable

**Admin Approval Workflow:**
1. Admin reviews registration request in Security Console
2. On approval, user is **fully provisioned** as department member:
   - Vault secret created with admin-specified password
   - Role inherited from department (Developer, Finance, HR, Sales, Admin)
   - Home region copied from existing department peers
   - Prevents "Unknown" geo status that would trigger false anomalies
3. Credentials emailed to security admin
4. User can immediately login with issued credentials

**Security Features:**
- Department-based role assignment ensures proper access controls
- Known home region baseline prevents initial anomaly false positives
- VPN detection flags suspicious registration attempts
- All approvals/rejections logged to audit trail with admin attribution

### Email Notification System

Strategic email alerts configured via `SOAR_*` environment variables (Gmail SMTP):

**Email Triggers:**
- **Vault Initialization:** Complete table of seeded users with initial passwords
- **Credential Rotation:** New password notification for affected user
- **VPN Detection:** User, source IP, ISP, and geolocation of VPN/proxy logins
- **User Provisioning:** Credentials sent to admin after registration approval

**Excluded:** Per-CRITICAL threat emails (removed to prevent Gmail rate limits). Critical alerts stream live to admin console via WebSocket instead.

## Technologies Used

### Frontend
- **Framework:** React 18.3 with Vite 5.4 build tooling
- **3D Visualization:** three-globe / globe.gl (WebGL-accelerated geospatial projections)
- **Styling:** Modern CSS3 with cyberpunk-inspired design system

### Backend
- **API Framework:** Python 3.11+ with FastAPI (asynchronous API and WebSockets)
- **Machine Learning:** scikit-learn, XGBoost, LightGBM (ensemble model with 97.3% accuracy)
- **Database:** PostgreSQL 16 (user accounts, metrics, append-only audit log)

### Infrastructure
- **Message Broker:** Apache Kafka 3.7.0 (KRaft mode, event streaming)
- **Search & Analytics:** Elasticsearch 8.15.0 + Kibana 8.15.0
- **Secrets Management:** HashiCorp Vault 1.15.6 (Raft storage, AppRole authentication)
- **Caching:** Redis 7 (WebSocket pub/sub, user profile caching)
- **Orchestration:** Docker Compose + Kubernetes (Minikube for local, production-ready manifests)
- **CI/CD:** GitHub Actions with automated testing, security scanning, and GHCR image publishing

---

## Project Directory Structure

```
hpe/
├── backend/                    # 🐍 Python FastAPI Microservice Backend
│   ├── app/
│   │   ├── routes/             # API routes (auth, admin, health, predict, etc.)
│   │   ├── db.py               # PostgreSQL connection & query execution
│   │   ├── kafka_client.py     # Kafka consumer & producer client
│   │   ├── redis_client.py     # Redis pub/sub for WebSocket broadcasting
│   │   ├── main.py             # FastAPI app entrypoint & lifecycle management
│   │   ├── threat_engine.py    # AI threat scoring & pipeline orchestration
│   │   ├── inference.py        # ML model loading & prediction
│   │   ├── vault_client.py     # HashiCorp Vault user credential management
│   │   ├── vault_infra_client.py # Infrastructure credential rotation
│   │   ├── auth_admin.py       # JWT-based admin authentication
│   │   ├── admin_store.py      # Alert and audit state management
│   │   ├── drift_monitor.py    # Model drift detection service
│   │   ├── soar_email.py       # Email alert notifications
│   │   └── ws_manager.py       # WebSocket connection manager
│   └── Dockerfile              # Dockerfile for Backend (Python 3.11-slim)
├── frontend/                   # ⚛️ React + Vite Dashboard
│   ├── src/
│   │   ├── components/         # React components (Dashboard, Globe, Pipeline, Admin, etc.)
│   │   ├── styles/
│   │   │   └── index.css       # Complete design system (cyberpunk-inspired)
│   │   ├── App.jsx             # Main application with routing
│   │   └── main.jsx            # React entrypoint
│   ├── index.html              # Main HTML entrypoint
│   └── Dockerfile              # Dockerfile for Frontend (Node 24)
├── public-login/               # 🌐 Nginx-based Public Enterprise Portal
│   ├── index.html              # Public portal UI (login/register)
│   ├── styles.css              # Cyberpunk-style login styling
│   └── nginx.conf              # Nginx routing configuration
├── beats/                      # Log Harvesters & Shippers
│   ├── filebeat.yml            # Core Filebeat config
│   ├── filebeat-live.yml       # Live mode Filebeat parser (dissects Zeek TSV fields)
│   └── filebeat-kafka.yml      # Native Kafka filebeat exporter
├── k8s/                        # ☸️ Kubernetes Manifests
│   ├── namespace.yaml          # hpe namespace definition
│   ├── configmap.yaml          # Shared environment configuration
│   ├── secrets.yaml            # Sensitive configuration values
│   ├── vault-pvc.yaml          # Persistent volume for Vault data
│   ├── postgres/               # PostgreSQL StatefulSet & Service
│   ├── kafka/                  # Kafka StatefulSet (2 brokers) & Services
│   ├── elasticsearch/          # Elasticsearch StatefulSet & Service
│   ├── kibana/                 # Kibana Deployment & Service
│   ├── redis/                  # Redis Deployment & Service
│   ├── vault/                  # Vault StatefulSet, Init Job, RBAC
│   ├── backend/                # Backend Deployment (5 replicas) & Service
│   ├── frontend/               # Frontend Deployment (3 replicas) & Service
│   └── live-pipeline/          # Optional: Live replay components
├── .github/
│   └── workflows/
│       ├── ci-cd.yml           # Complete CI/CD pipeline with security scanning
│       ├── ml-pipeline.yml     # ML model training & artifact generation
│       └── retrain.yml         # Scheduled model retraining workflow
├── docker-compose.yml          # Full stack (dataset replay + zeek + filebeat)
├── docker-compose.portal.yml   # Portal-only stack (live logins only, no dataset replay)
├── run-portal.bat              # One-click portal-only launcher (Windows)
├── run-compose.bat             # One-click full stack launcher (Windows)
├── run-local.bat               # Local demo one-click launcher (Windows)
├── vault/
│   ├── config/
│   │   └── vault.hcl           # HashiCorp Vault cluster configuration
│   └── init/
│       └── init-vault.sh       # Automated Vault initialization job (AppRole setup, DB engines)
├── scripts/                    # Utility Pipelines & Replay Engines
│   ├── mode_switcher.py        # Host-side agent (port 9001) for the dashboard Live/Portal toggle
│   ├── replay_live.py          # Synthetic dataset network live replay writer
│   ├── es_to_kafka.py          # Elasticsearch to Kafka bridge script (watch-optimized)
│   ├── generate_conn_log_from_test_events.py  # Build a conn.log from test_events.json (uid=event_id)
│   └── generate_zeek_pcap.py   # Synthetic PCAP generation
└── dataset/                    # Network Telemetry Training Logs
    ├── updated_realistic_network_logs.csv  # 100k+ network event records
    ├── updated_realistic_user_profiles.csv  # Behavioral profiles
    └── zeek-live/              # Log harvester target workspace
```

---

## Default Access Ports & Login Credentials

### Ports & URL Mappings

| Service | Local URL / Access | Description |
|---------|---------------------|-------------|
| **3D Security Dashboard** | [http://localhost:5173](http://localhost:5173) | Main Bento-style threat visualizer |
| **Enterprise Login Portal** | [http://localhost:8080](http://localhost:8080) | Public portal vulnerable to brute force / VPN threats |
| **FastAPI Backend API** | [http://localhost:8000](http://localhost:8000) | Microservice threat scoring & WebSocket broker |
| **Adminer Database Manager** | [http://localhost:9090](http://localhost:9090) | GUI database administrator |
| **PostgreSQL Audit DB** | `localhost:5432` | Standard relational log datastore |
| **HashiCorp Vault Server** | [http://localhost:8200](http://localhost:8200) | Secrets storage & dynamic credential provider |
| **Elasticsearch Node** | [http://localhost:9200](http://localhost:9200) | Big data indexer & analyzer |
| **Kibana Log Dashboard** | [http://localhost:5601](http://localhost:5601) | Elasticsearch visualization suite |
| **Apache Kafka Broker** | `localhost:9092` | Stream buffer engine |

### Database Credentials (PostgreSQL)

*   **Database Host:** `hpe-postgres` (Inside Docker network) or `localhost` (Host system)
*   **Database Port:** `5432`
*   **Database Name:** `hpedb`
*   **Superuser/Root Account:**
    *   **Username:** `vault-root`
    *   **Password:** `vault-root-secret`
*   **Vault Managed Service Account:** Dynamic roles generated by Vault under `database/creds/hpe-app`. These are rotated automatically on threat approvals.

### Seed User Accounts (Enterprise Portal)

Log in to the **Enterprise Portal** (`http://localhost:8080/`) using these pre-configured credentials:

| Username | Password | Department / Role | Status |
|----------|----------|-------------------|--------|
| `admin` | `admin` | Security (Admin / Audit) | Active |
| `alice` | `password123` | Engineering (Developer) | Active |
| `bob` | `password123` | HR (Employee) | Active |
| `charlie` | `password123` | Finance (Employee) | Active |

#### Additional Test Users

At startup, the backend dynamically seeds **200 user profiles** (loaded from `user_profiles.json`) with IDs `USR-0001` through `USR-0200` into PostgreSQL and HashiCorp Vault.

**Demo Credential Helper:** The login page includes a dropdown helper that lists all active users. Three curated demo accounts (`USR-0001` Developer, `USR-0002` Finance, `USR-0005` Admin, marked with ★) reveal their passwords and support autofill. Other accounts show masked credentials (`••••••••`) — full credentials are emailed to the admin during Vault initialization.

---

## Project Setup

The HPE pipeline supports **four deployment modes** to accommodate different use cases:

| Mode | Best For | Infrastructure Required |
|------|----------|------------------------|
| **Portal-Only (Docker)** | Live demos, presentations, public access | Docker Desktop |
| **Full Stack (Docker)** | End-to-end pipeline with dataset replay | Docker Desktop (8GB+ RAM) |
| **Kubernetes (Minikube)** | Production-grade HA deployment | Minikube + kubectl |
| **Local Dev (No Docker)** | UI development, low-resource machines | Python 3.11+ + Node 24+ |

---

### Prerequisites (All Modes)

**1. Generate ML Model Artifacts** (required once, or after dataset changes):

```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```

This creates:
- `model_output/pipeline_artifacts_v2.joblib` — Trained ensemble model
- `model_output/test_events.json` — ~3500 test events for simulation
- `model_output/user_profiles.json` — 200 user profiles with behavioral baselines

---

### Option 1: Portal-Only Mode (Docker Compose) 🌐

**Recommended for:** Live demonstrations, presentations, and public access via Ngrok

**Description:** Events enter the pipeline **only** from real user logins or threat simulation interactions — no background dataset replay. This provides complete control: nothing appears in the pipeline unless deliberately triggered.

**Services Running (11 containers):**

| Container | Role |
|-----------|------|
| `hpe-backend` | FastAPI AI engine + WebSocket broker |
| `hpe-frontend` | React dashboard (port 5173) |
| `hpe-kafka` | Event streaming broker (KRaft mode) |
| `hpe-elasticsearch` | Log storage & search engine |
| `hpe-kibana` | Log visualization UI (port 5601) |
| `hpe-postgres` | User accounts + audit database |
| `hpe-vault` | Secrets & credential management |
| `hpe-redis` | Session cache & WebSocket pub/sub |
| `hpe-login-portal` | Nginx enterprise login portal (port 8080) |
| `hpe-adminer` | Database management UI (port 9090) |
| `hpe-ngrok` | Public tunnel with inspector (port 4040) |

**Data Flow:**
```
User Login / Threat Simulation
  → Backend API → AI Engine
  → WebSocket Broadcast → Dashboard
```

#### 🚀 Quick Start (Windows)

**One-Click Launch:**
```bat
run-portal.bat
```

The launcher automatically:
1. Stops any previously running containers
2. Rebuilds images with latest code
3. Starts portal-only services
4. Waits for backend health check
5. Retrieves Ngrok public URL
6. Opens dashboard in browser

#### 🛠️ Manual Commands

**Start Services:**
```bash
# Clean any previous deployments
docker-compose -f docker-compose.portal.yml down --remove-orphans
docker-compose down --remove-orphans

# Start portal-only mode
docker-compose -f docker-compose.portal.yml up -d --build --remove-orphans
```

**Rebuild After Code Changes:**
```bash
# Force full rebuild (bypasses Docker cache)
docker-compose -f docker-compose.portal.yml build --no-cache frontend backend
docker-compose -f docker-compose.portal.yml up -d --remove-orphans
```

**Stop Services:**
```bash
docker-compose -f docker-compose.portal.yml down --remove-orphans
```

**Complete Reset (wipe all data):**
```bash
# Removes all volumes (Vault secrets, Postgres data, Kafka topics)
docker-compose -f docker-compose.portal.yml down --remove-orphans -v
```

> **Important:** Always run `down --remove-orphans` before switching between portal-only and full-stack modes. Both compose files share container names and networks.

---

### Option 2: Full Enterprise Stack (Docker Compose) 🐳

**Recommended for:** Complete end-to-end pipeline testing with continuous data flow

**Description:** Runs the complete infrastructure including optional Zeek IDS, Filebeat log shipping, dataset replay, and all portal services. Synthetic network events stream continuously through the full 10-stage pipeline.

**Prerequisites:**
* Docker Desktop with **8GB+ memory** allocated (required for Elasticsearch)
* Python 3.11+ installed locally (for model generation)

#### 🚀 Quick Start (Windows)

**One-Click Launch:**
```powershell
.\run-compose.bat
```

**Automated Setup Process:**
1. Verifies Docker is running
2. Generates ML models if missing
3. Starts full stack with live-replay profile
4. Waits for service health checks
5. Extracts Ngrok public URL

**First Boot:** Allow 2-3 minutes for all services to initialize.

#### 🛠️ Manual Startup

**Start Full Stack with Dataset Replay:**
```bash
docker-compose --profile live-replay up -d --build --remove-orphans
```

**Stop Services:**
```bash
docker-compose --profile live-replay down --remove-orphans
```

**Access Points:**
* **3D Security Dashboard:** http://localhost:5173
* **Enterprise Login Portal:** http://localhost:8080
* **Database Manager:** http://localhost:9090
* **Kibana:** http://localhost:5601
* **Vault UI:** http://localhost:8200

#### Restart After Docker Down

If you stop with `docker-compose down` (without `-v`), Vault starts sealed on next boot. Re-unseal automatically:

```bash
docker-compose restart vault vault-init
docker-compose restart backend login-portal
```


---

### Mode Switching from Dashboard 🔀

The dashboard header includes a **MODE** toggle that switches between deployment modes without touching the terminal.

**Host-Side Agent Setup:**

The mode switcher requires a lightweight Python agent running on the host (since the toggle needs to control Docker Compose):

```bash
python scripts/mode_switcher.py
```

**Agent runs on port 9001 and provides:**
- `GET  /status` — Current mode and busy state
- `POST /switch/live` — Switch to live-replay mode (fast, no rebuild)
- `POST /switch/portal` — Switch to portal-only mode (fast, no rebuild)
- `POST /rebuild/live` — Switch and rebuild (use after code changes)
- `POST /rebuild/portal` — Switch and rebuild (use after code changes)

**How It Works:**
1. Agent detects current mode by checking running containers
2. Dashboard button calls agent API endpoints
3. Agent executes `docker-compose down` + `up` with appropriate profile
4. Mode switches use plain `up -d` for speed (rebuilds only when explicitly requested)

**Important Notes:**
- Run only **one** agent instance (second instance fails with "address already in use")
- Agent must stay running for dashboard toggle to work
- Use `/rebuild/*` endpoints only after code changes (preserves BuildKit cache)

#### Event Feed by Mode

| Mode | Event Source | Dashboard Display |
|------|-------------|-------------------|
| **Live Replay** | Simulate WebSocket streams labeled `test_events.json` into Kafka (~2 events/sec) | Real user IDs (`USR-XXXX`) with model-driven anomaly scores |
| **Portal** | Only real portal logins + manual threat simulations (`PORTAL_ONLY_MODE=true`) | No events until user action |

**Technical Details:**
- Synthetic events use a **single shared Kafka producer** (one per backend instance)
- Kafka consumer **seeks to latest offset** on connect (shows current events, not stale backlog)
- Raw Zeek/pcap path is **opt-in** via `live-replay` profile (generates identity-less events)
- Default feed is the labeled Simulate WebSocket for better visualization

---

### Option 3: Kubernetes Deployment (Minikube) ☸️

**Recommended for:** Production-grade, high-availability deployment with horizontal scaling

**Description:** Deploys the entire pipeline into a Kubernetes cluster with HA replicas, StatefulSets for stateful services, and automated secrets management via Vault initialization Job.

#### Architecture Overview

| Component | K8s Resource | Replicas | Features |
|-----------|-------------|----------|----------|
| Kafka | StatefulSet | 2 | KRaft mode, headless service |
| Elasticsearch | StatefulSet | 1 | Single-node dev mode, 1Gi PVC |
| PostgreSQL | StatefulSet | 1 | Schema init via ConfigMap |
| Redis | Deployment | 1 | Pub/sub for WebSocket broadcasting |
| Vault | StatefulSet | 1 | Raft storage, auto-unseal sidecar |
| Vault Init | Job | 1 (run-once) | 5-phase init: unseal, DB engine, AppRole |
| Backend | Deployment | 5 | Init container waits for dependencies |
| Frontend | Deployment | 3 | Vite dev server with NodePort |

#### Prerequisites

* **Minikube** installed and running
* **kubectl** configured for Minikube cluster
* **Docker CLI** available
* Python 3.11+ (for model generation)

#### Step 1: Start Minikube

```bash
minikube start --memory=8192 --cpus=4
```

#### Step 2: Generate ML Artifacts

```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```

#### Step 3: Deploy with Automated Script (Windows PowerShell)

**One-Shot Deployment:**
```powershell
.\deploy.ps1
```

**Available Options:**
```powershell
# Skip image rebuilds (faster if images exist)
.\deploy.ps1 -SkipBuild

# Delete namespace first for clean slate
.\deploy.ps1 -DeleteFirst

# Deploy and wipe pipeline data after startup
.\deploy.ps1 -Fresh
```

**Deployment Phases (Automated):**
1. **Configure Docker** — Points Docker CLI at Minikube's daemon
2. **Build Images** — `hpe-backend:latest` and `hpe-frontend:latest` inside Minikube
3. **Create Namespace + Config** — Applies namespace, ConfigMap, Secrets, PVC
4. **Deploy Infrastructure** — PostgreSQL, Kafka (2 brokers), Elasticsearch, Redis, Vault
5. **Vault Initialization** — Runs vault-init Job (5 phases)
6. **Deploy Application** — Backend (5 replicas) + Frontend (3 replicas)
7. **Enable HPA** — Horizontal Pod Autoscaler for backend

#### Step 4 — Manual deployment (Linux/Mac or if not using PowerShell)

If you are **not** on Windows PowerShell, run the equivalent commands manually:

```bash
# Point Docker to Minikube
eval $(minikube docker-env)

# Build images inside Minikube
docker build -t hpe-backend:latest -f backend/Dockerfile .
docker build -t hpe-frontend:latest -f frontend/Dockerfile ./frontend

# Create namespace and config
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secrets.yaml
kubectl apply -f k8s/vault-pvc.yaml

# Deploy infrastructure
kubectl apply -f k8s/postgres/
kubectl apply -f k8s/kafka/
kubectl apply -f k8s/elasticsearch/

# Apply Vault RBAC before the StatefulSet so the ServiceAccount exists when the pod schedules
kubectl apply -f k8s/vault/vault-rbac.yaml
kubectl apply -f k8s/vault/vault-config-configmap.yaml
kubectl apply -f k8s/vault/vault-service.yaml
kubectl apply -f k8s/vault/vault-statefulset.yaml

# Wait for infrastructure pods
kubectl wait --for=condition=Ready pod -l app=kafka -n hpe --timeout=240s
kubectl wait --for=condition=Ready pod -l app=elasticsearch -n hpe --timeout=180s
kubectl wait --for=condition=Ready pod -l app=vault -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=postgres -n hpe --timeout=120s

# Run Vault init Job
kubectl apply -f k8s/vault/vault-init-configmap.yaml
kubectl apply -f k8s/vault/vault-init-job.yaml
kubectl wait --for=condition=Complete job/vault-init -n hpe --timeout=180s

# Deploy application
kubectl apply -f k8s/backend/
kubectl apply -f k8s/frontend/

# Wait for app pods
kubectl wait --for=condition=Ready pod -l app=backend -n hpe --timeout=120s
kubectl wait --for=condition=Ready pod -l app=frontend -n hpe --timeout=120s
```

#### Step 5 — Access the dashboard
```bash
minikube service frontend -n hpe
```
This opens a browser tunnel to the frontend NodePort service.

#### Useful Kubernetes Commands
```bash
# Check pod status
kubectl get pods -n hpe

# View logs for a specific pod
kubectl logs -f deployment/backend -n hpe

# View Vault init logs
kubectl logs job/vault-init -n hpe

# View auto-unseal sidecar logs
kubectl logs vault-0 -c unseal-watcher -n hpe

# Port-forward backend for direct API access
kubectl port-forward service/backend 8000:8000 -n hpe

# Tear down everything
kubectl delete namespace hpe
```

#### Vault Unsealing After Restart

> **Why does Vault seal itself?**
> Vault uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) as a security mechanism. Every time Vault's container restarts (e.g., after `minikube stop` → `minikube start`), Vault deliberately seals itself. This is **by design** — if someone gains physical access to the server, they cannot read any secrets without the unseal key.

Unsealing is handled automatically. The Vault pod runs an `unseal-watcher` sidecar container that polls Vault's seal status every 15 seconds and calls the unseal API whenever it detects Vault has sealed itself after a restart — no manual steps required.

If the dashboard shows **Vault** as red (🔴) after a Minikube restart, the sidecar will restore it automatically within 15 seconds. You can watch it in real time:

```bash
kubectl logs vault-0 -c unseal-watcher -n hpe -f
```

Once Vault is unsealed, restart the backend so it reconnects:
```bash
kubectl rollout restart deployment/backend -n hpe
```

After this, refresh the dashboard — the Vault indicator should turn green (🟢).

---

### Option 4: Local Demo Mode (No Docker) 💻
*Recommended for UI development or low-resource machines.*

If you do not want to spin up the heavy infrastructure containers, you can run the backend and frontend scripts directly on your local system. The dashboard will intelligently fall back to generating simulation traffic locally.

#### 🚀 Recommended Fast Startup (One-Click)

We have provided a **one-shot local launcher** that automates the entire local setup process.

On **Windows PowerShell / Command Prompt**, simply run:
```bash
run-local
```

**What the launcher script does for you:**
1. **Verifies Prerequisites:** Confirms Python 3.10+ and Node.js (v18+) are installed.
2. **Generates ML Models:** Checks if machine learning pipeline artifacts are present. If missing, it installs the necessary packages and generates them automatically.
3. **Creates Python Venv:** Creates a virtual environment in `backend/venv` and runs `pip install` for backend dependencies.
4. **Installs Node Modules:** Installs required packages in the `frontend` folder if missing.
5. **Starts Application Services:** Boots the FastAPI backend on port `8000` and the Vite frontend on port `5173` in separate popped-up console windows.
6. **Autoplays Browser:** Automatically opens `http://localhost:5173` in your default web browser.

---

#### 🛠️ Manual Startup (Alternative)

If you prefer starting components manually:

**Step 1: Generate model artifacts (if not already done):**
```bash
pip install xgboost lightgbm scikit-learn pandas numpy joblib imbalanced-learn
python export_v2_model.py
```

**Step 2: Start the Backend (API & Simulation)**
```bash
cd backend

# Create a virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server
uvicorn app.main:app --reload --port 8000
```
*Because Kafka and Elastic are not active, the backend API will safely fallback into test mode.*

**Step 3: Start the Frontend (3D UI)**
Open a **new** terminal window and run:
```bash
cd frontend

# Install Node modules
npm install

# Start the Vite development server
npm run dev
```
Navigate to **http://localhost:5173**. The application will automatically use "Local Simulation" mode.

---

### Admin API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/admin/login` | None | Exchange Security department credentials for a JWT |
| GET | `/api/admin/alerts` | JWT | List all alerts (filter: `?status=pending&severity=critical`) |
| GET | `/api/admin/alerts/{id}` | JWT | Full forensic detail for an alert |
| POST | `/api/admin/alerts/{id}/approve` | JWT | Approve credential rotation (logs admin attribution) |
| POST | `/api/admin/alerts/{id}/reject` | JWT | Reject as false positive (logs admin attribution) |
| GET | `/api/admin/stats` | JWT | Dashboard summary statistics |
| GET | `/api/admin/audit-log` | JWT | History of admin actions |
| GET | `/api/admin/infra-leases` | JWT | Active Vault infrastructure leases and Kafka credential status |
| GET | `/api/admin/registrations` | JWT | List pending user access requests |
| POST | `/api/admin/registrations/{user}/approve` | JWT | Approve a pending user and set credentials |
| POST | `/api/admin/registrations/{user}/reject` | JWT | Reject and delete a pending registration |
| POST | `/api/admin/reset/request` | JWT | Generate a one-time pipeline reset token (60s TTL) |
| POST | `/api/admin/reset/confirm` | JWT | Execute pipeline reset with a valid confirmation token |
| WS | `/api/admin/ws` | JWT (query param) | Real-time alert notifications |

### Authentication & Threat Simulation Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | None | Validate credentials; returns role + login memory. Rotates credentials on brute-force login (>5 failed attempts in 5 min) |
| POST | `/api/auth/register` | None | Submit a new account registration (pending admin approval) |
| POST | `/api/auth/simulate` | None | Run real-time threat simulation with custom geo/VPN/download parameters (forces Vault credential rotation if BLOCK/CRITICAL; auto-detects impossible travel) |
| GET | `/api/auth/users` | None | Retrieve list of active portal users and their roles |
| GET | `/api/auth/demo-users` | None | List the 3 curated demo accounts whose passwords are shown in the credential helper |
| GET | `/api/auth/login-history/{user_id}` | None | Login memory: last session time, region, IP, and recorded failed-attempt count |
| GET | `/api/auth/user-profile/{user_id}` | None | Get user machine learning baseline profile |
| GET | `/api/auth/user-credential/{user_id}` | None | Retrieve cleartext login password for a user from HashiCorp Vault |

---

### Kubernetes Manifest Structure
```
k8s/
├── namespace.yaml              # hpe namespace
├── configmap.yaml              # Shared env vars (Kafka, ES, Vault URLs)
├── secrets.yaml                # VAULT_TOKEN fallback secret
├── vault-pvc.yaml              # Shared PVC for Vault data + AppRole creds
├── kafka/
│   ├── kafka-headless-service.yaml   # Headless service (publishNotReadyAddresses)
│   └── kafka-statefulset.yaml        # 2-broker KRaft cluster
├── elasticsearch/
│   ├── es-service.yaml
│   └── es-statefulset.yaml
├── postgres/
│   ├── postgres-init-configmap.yaml  # Schema, pgcrypto, tables
│   ├── postgres-service.yaml
│   └── postgres-statefulset.yaml
├── live-pipeline/
│   ├── es-to-kafka-deployment.yaml
│   ├── live-pipeline-configmap.yaml
│   └── live-replay-deployment.yaml
├── redis/
│   ├── redis-deployment.yaml
│   └── redis-service.yaml
├── vault/
│   ├── vault-rbac.yaml               # ServiceAccount, Role, RoleBinding for Vault pod
│   ├── vault-config-configmap.yaml   # vault.hcl server config
│   ├── vault-init-configmap.yaml     # Full init script (Phases 1-5)
│   ├── vault-init-job.yaml           # One-shot init Job
│   ├── vault-service.yaml
│   └── vault-statefulset.yaml        # Includes auto-unseal sidecar
├── backend/
│   ├── backend-deployment.yaml       # 5 replicas + init container
│   ├── backend-hpa.yaml              # Horizontal Pod Autoscaler
│   └── backend-service.yaml
└── frontend/
    ├── frontend-deployment.yaml      # 3 replicas
    └── frontend-service.yaml
```

---

### Dataset

The training dataset is included in `dataset/`:
- `updated_realistic_network_logs.csv` — 100K+ network events with injected anomalies
- `updated_realistic_user_profiles.csv` — User behavioral profiles

---

#### Pipeline Mode 1: One-Shot (Dataset → Zeek → Beats → ES → Kafka)

Process the entire dataset through the pipeline in a single pass:

1. Generate a synthetic PCAP from the CSV (or capture live network traffic):
   ```bash
   # Synthetic mode (default)
   python scripts/generate_zeek_pcap.py
   
   # Live capture mode (requires scapy: pip install scapy)
   python scripts/generate_zeek_pcap.py --live --duration 60 --interface eth0
   ```
2. Start Zeek and Filebeat via Docker Compose:
   ```bash
   docker compose up -d zeek filebeat elasticsearch kafka
   ```
3. Filebeat reads `dataset/zeek/conn.log` and ships events into Elasticsearch.
4. Run the Elasticsearch → Kafka bridge service:
   ```bash
   docker compose up -d es-to-kafka
   ```
   This executes `scripts/es_to_kafka.py` (now with `--watch` mode) and continuously publishes documents from `zeek-conn-*` into Kafka topic `hpe-raw-events`.

---

#### Pipeline Mode 2: Live Replay (Dataset streamed as live traffic)

Replay the dataset as if it were live network traffic — events arrive one at a time at a controlled rate through the full pipeline:

```
scripts/replay_live.py ──writes──▶ dataset/zeek-live/conn.log
                                   │
                              Filebeat (tail mode)
                                   │
                              Elasticsearch
                                   │
                              scripts/es_to_kafka.py (--watch)
                                   │
                                 Kafka  ──▶  AI Backend
```

**Option A — Via Docker Compose (recommended):**
```bash
# Start the core infrastructure + live replay pipeline
docker compose up -d elasticsearch kafka
docker compose --profile live-replay up -d

# Also start the ES→Kafka bridge
docker compose up -d es-to-kafka

# Adjust replay speed via environment variable (default: 50 events/sec)
REPLAY_RATE=100 docker compose --profile live-replay up -d
```

**Option B — Direct to Kafka (skip ES bridge, lowest latency):**
```bash
docker compose up -d kafka
docker compose --profile live-kafka up -d

# scripts/replay_live.py must also be running to feed events
python scripts/replay_live.py --rate 50 --loop
```

**Option C — Run replay locally (no Docker for replay):**
```bash
# Start infrastructure in Docker
docker compose up -d elasticsearch kafka

# Run replay on your local machine
python scripts/replay_live.py --rate 50 --loop

# Start filebeat-live in Docker (it reads dataset/zeek-live/)
docker compose --profile live-replay up -d filebeat-live
docker compose up -d es-to-kafka
```

**Replay script options:**
```bash
python scripts/replay_live.py --help

# Default: 50 events/sec, one pass
python scripts/replay_live.py

# Custom rate, infinite loop
python scripts/replay_live.py --rate 100 --loop

# Burst mode (max speed), 3 passes
python scripts/replay_live.py --rate 0 --repeat 3

# Clean previous output first
python scripts/replay_live.py --clean --loop
```

To retrain the model, run:
```bash
python export_v2_model.py
```

---

### Teardown 🛑

**Portal-Only Mode:**
```bash
# Graceful stop
docker compose -f docker-compose.portal.yml down --remove-orphans

# Hard reset (wipes Vault secrets, Postgres users, Kafka topics, ES indices)
docker compose -f docker-compose.portal.yml down --remove-orphans -v
```

**Full Stack Mode:**
```bash
# Graceful stop
docker compose --profile live-replay down --remove-orphans

# Hard reset
docker compose --profile live-replay down --remove-orphans -v
```

**Stop everything (both modes at once):**
```bash
docker compose -f docker-compose.portal.yml down --remove-orphans && docker compose down --remove-orphans
```

> Always use `--remove-orphans` when tearing down. Without it, containers from the other compose file that share the same Docker network are left running as orphans and continue consuming resources.

**Kubernetes (Minikube):**
```bash
# Delete everything in the hpe namespace
kubectl delete namespace hpe

# Optionally stop Minikube
minikube stop
```

After a hard reset (`-v`), re-run `python export_v2_model.py` before starting again.

---

### Model Performance Gate

The ML pipeline enforces a minimum **Threat class F1 score of 0.70** before a trained model can be uploaded as a CI artifact. The gate runs automatically on every push that touches `export_v2_model.py`, the dataset, or the inference code. If the score falls below the threshold, the workflow exits non-zero and blocks the artifact upload.

The threshold is controlled by `MIN_F1_THRESHOLD` in `.github/workflows/ml-pipeline.yml`. After each successful run, a formatted results table (F1, precision, recall, best threshold, training duration) is written to the GitHub Actions job summary and visible directly in the PR UI.

## Contributors

This project was developed by the HPE Enterprise Security team:

- [Adi Narayan Prasad G](https://github.com/Prasadadi18)
- [Alka Kumari](https://github.com/alka104)
- [Brijesh Shetty N](https://github.com/brijesh-shetty)
- [Shreyas S](https://github.com/shreyassridhar44)
- [Vishruth Vijaykumar](https://github.com/cheeseburden)

---
