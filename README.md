# HPE: Enterprise Network Threat Detection Pipeline


HPE is a production-grade, AI-powered cybersecurity threat detection pipeline. It simulates a modern Security Operations Center (SOC) backend and visualizes real-time network traffic interceptions via a stunning 3D WebGL interface, a Structural Spatial (Bento Box) dashboard, and a **Security Admin Console** with human-in-the-loop credential rotation.

## Overview

The system is designed to ingest raw network traffic, extract behavioral features, execute high-speed machine learning inference in a microservice backend, and trigger automated orchestrated responses (like HashiCorp Vault credential rotation) when a zero-day or malicious pattern is detected.

**Key Feature: Human-in-the-Loop Approval**
For BLOCK and CRITICAL severity threats, credential rotation is **not automatic**. Instead, the system creates a pending alert that an admin must review and approve before Vault rotates credentials. This ensures human oversight over high-impact security actions.

### The Pipeline Architecture

The dashboard visually maps and documents an enterprise-grade 10-stage pipeline. Here is exactly what happens during a real-time event:

1. **Network / Apps:** We continuously monitor network traffic across the enterprise. Raw data packets (PCAP) from routers and application logs are collected and converted into a standard format, providing the foundational telemetry stream for our security pipeline.
2. **Zeek / Suricata (IDS):** Traffic passes through an Intrusion Detection System (IDS). Tools like Suricata and Zeek perform Deep Packet Inspection (DPI) to quickly scan for known malicious patterns and extract useful network metadata (like HTTP or DNS info).
3. **Elastic Beats:** To keep data organized, we use log shippers like Filebeat. They collect raw logs from the IDS, clean them up into a standardized format called the Elastic Common Schema (ECS), and map IP addresses to geographic locations.
4. **Apache Kafka:** To transport this massive amount of data smoothly, we use Apache Kafka as a high-throughput event streaming broker. It acts as an immutable buffer, ensuring our AI Engine isn't overwhelmed during sudden spikes in network traffic.
5. **AI Detection Engine:** The core brain of the system. Our FastAPI microservice consumes the Kafka stream and engineers complex behavioral features in split-seconds. It relies on a state-of-the-art AI ensemble (XGBoost, LightGBM, Random Forest, Gradient Boosting) to predict if an event is a novel, previously unseen threat.
6. **SOAR:** If the AI flags a threat, our SOAR (Security Orchestration, Automation, and Response) platform takes over. Rather than waiting for a human analyst, it automatically triggers conditional incident response playbooks—like isolating machines or initiating automated password resets.
7. **HashiCorp Vault (Human-in-the-Loop):** For BLOCK/CRITICAL threats, the system creates a **pending admin alert** instead of auto-rotating credentials. The admin must review the forensic data, model scores, and pipeline results before approving the rotation.
8. **Credential Rotation:** Once approved by an admin, Vault executes a secure credential rotation. It instantly invalidates old, hijacked sessions and generates cryptographically secure, brand-new passwords and API keys for our databases and services.
9. **Credential Distribution:** Once new passwords are created, they must be distributed safely. The system automatically pushes these new Vault secrets back to our servers and active microservices using encrypted TLS tunnels, restoring security without taking the system offline.
10. **ELK / Grafana:** Finally, every single event—safe traffic or neutralized threat—is permanently recorded. We index all data into an Elasticsearch database, allowing human analysts to search audit logs and view real-time visualizations on Kibana dashboards.

### Security Admin Console

The admin dashboard provides:
- **Real-time Alert Queue** — Critical and high-severity threats appear as pending alerts
- **Forensic Detail View** — Full event facts, model scores (XGBoost, LightGBM, Ensemble), geo data, and all 10 pipeline stage results
- **Approve / Reject Workflow** — One-click credential rotation approval or false positive rejection
- **Audit Log** — Complete history of all admin actions with timestamps and notes
- **WebSocket Notifications** — Instant toast alerts when new critical threats are detected

## Technologies Used

* **Frontend:** Vanilla JavaScript, Vite, HTML5, CSS3 (Structural Cyber-Bento styling).
* **3D Visualization:** `three-globe` / `globe.gl` (WebGL-accelerated geospatial projections).
* **Backend:** Python 3.10+, FastAPI (Asynchronous API and WebSockets).
* **Machine Learning:** `scikit-learn`, `xgboost`, `lightgbm` (Feature Engineering and Ensembling).
* **Infrastructure Layer:** Docker Compose (Kafka, Zookeeper/KRaft, Elasticsearch, HashiCorp Vault).

## Project Setup

You can run this project in two ways: the full enterprise stack (via Docker) which runs all services in real-time, or a standalone local demo mode for testing the UI.

---

### Option 1: Full Enterprise Stack (Docker Compose) 🐳
*Recommended for production environments.* 

This method will automatically download, build, and orchestrate all 6 containers: Kafka, Elasticsearch, Kibana, HashiCorp Vault, the Python AI Backend, and the Vite Frontend.

1. Ensure Docker Desktop is running and has at least **8GB of Memory** allocated (required for Elastic).
2. Open a terminal in the root directory and run:
   ```bash
   docker-compose up --build
   ```
   *(Note: It may take 30-60 seconds for the infrastructure healthchecks—specifically Vault and Elastic—to initialize during the first boot. Please wait until they report as "Healthy".)*

3. Once all systems are healthy, open your browser and navigate to:
   **http://localhost:5173**

You will see the pipeline connecting to the live backend WebSocket and processing real infrastructure data. Navigate to the **Admin Console** (Section 4) to see pending threat alerts.

---

### Option 2: Local Demo Mode (No Docker) 💻
*Recommended for UI development or low-resource machines.*

If you do not want to spin up the heavy infrastructure containers, you can run the backend and frontend scripts directly on your local system. The dashboard will intelligently fall back to generating simulation traffic locally.

**Step 1: Start the Backend (API & Simulation)**
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

**Step 2: Start the Frontend (3D UI)**
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

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/alerts` | List all alerts (filter: `?status=pending&severity=critical`) |
| GET | `/api/admin/alerts/{id}` | Full forensic detail for an alert |
| POST | `/api/admin/alerts/{id}/approve` | Approve credential rotation |
| POST | `/api/admin/alerts/{id}/reject` | Reject as false positive |
| GET | `/api/admin/stats` | Dashboard summary statistics |
| GET | `/api/admin/audit-log` | History of admin actions |
| WS | `/api/admin/ws` | Real-time alert notifications |

---

### Dataset

The training dataset is included in `dataset/`:
- `updated_realistic_network_logs.csv` — 100K+ network events with injected anomalies
- `updated_realistic_user_profiles.csv` — User behavioral profiles

To retrain the model, run:
```bash
python export_v2_model.py
```

---

### Teardown (Stopping Docker) 🛑
To gracefully stop all running containers, open a terminal in the root directory and run:
```bash
docker-compose down
```
If you wish to perform a **hard reset** and wipe all saved databases (such as Elasticsearch logs and Kafka topics) to start fresh next time, use:
```bash
docker-compose down -v
```

## Team
HPE Code Project Interns
