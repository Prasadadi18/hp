# API Reference — AI-Based Network Monitoring and Anomaly Detection System

> **Backend API:** `http://localhost:8000` (Docker deployment)  
> **Interactive Documentation:** `http://localhost:8000/docs` (Swagger UI)

This document provides comprehensive API endpoint reference for the AI-Based Network Monitoring and Anomaly Detection System backend service.

---

## Health & Metrics

### `GET /api/health`
Full health check of all pipeline components.

**Response:**
```json
{
  "status": "healthy",
  "app_name": "HPE",
  "version": "1.0.0",
  "uptime_seconds": 142.3,
  "model_loaded": true,
  "kafka_connected": true,
  "elasticsearch_connected": true,
  "vault_connected": true,
  "total_requests": 57,
  "total_threats_blocked": 12
}
```

---

### `GET /api/metrics`
Detailed pipeline metrics including per-attack-type breakdown.

**Response:**
```json
{
  "total_requests": 57,
  "total_threats": 18,
  "total_allowed": 39,
  "total_monitored": 8,
  "total_blocked": 7,
  "total_critical": 3,
  "avg_latency_ms": 14.32,
  "model_metrics": { "accuracy": 0.973, "f1_score": 0.961 },
  "pipeline_health": {
    "kafka": "connected",
    "elasticsearch": "connected",
    "vault": "connected",
    "model": "loaded"
  },
  "attack_types": {
    "credential_stuffing": 6,
    "data_exfiltration": 4,
    "brute_force": 3
  }
}
```

---

## Pipeline

### `GET /api/pipeline/status`
Returns all 10 pipeline stages with real tool health.

**Response:**
```json
{
  "stages": [
    {
      "name": "Network / Apps",
      "stage_number": 1,
      "health": "active",
      "description": "..."
    },
    {
      "name": "Apache Kafka",
      "stage_number": 4,
      "health": "connected"
    },
    {
      "name": "HashiCorp Vault",
      "stage_number": 7,
      "health": "connected",
      "rotation_count": 5
    }
  ],
  "total_events_processed": 57
}
```

---

## Prediction

### `POST /api/predict`
Process a single network event through the full 10-stage pipeline.

**Request Body:** (NetworkEvent)
```json
{
  "user_id": "USR-0042",
  "source_ip": "192.168.1.105",
  "action": "file_download",
  "ip_region": "EU-Central",
  "bytes_sent": 1024,
  "bytes_received": 50000,
  "login_hour": 3,
  "download_volume_mb": 500.0,
  "geo_mismatch": true,
  "anomaly_type": "data_exfiltration"
}
```

**Response:** Full `PredictionResult` with all 10 pipeline stages, scores, geo coordinates.

---

## Vault Credentials

### `GET /api/vault/credentials`
Returns the most recently rotated user's masked credentials (used by dashboard polling).

**Response:**
```json
{
  "rotation_count": 5,
  "user_id": "USR-0042",
  "role": "Admin",
  "db_password": "A3$k****9!mZ",
  "api_key": "hpe_a1b2****",
  "service_token": "f47ac10b****",
  "created_at": "2026-04-24T17:30:00Z",
  "rotation_reason": "threat_detected_score_0.9231",
  "triggered_by_user": "USR-0042",
  "threat_score": 0.9231
}
```

---

### `GET /api/vault/users`
Returns masked credentials for **all 200 users** stored in Vault.

**Query Parameters:**
| Param | Type | Description |
|---|---|---|
| `role` | string | Filter by role: `Developer`, `Admin`, `Sales`, `Finance`, `HR` |
| `region` | string | Filter by region: `US-East`, `US-West`, `EU-Central`, `Asia-Pacific`, `South-America` |

**Example:** `GET /api/vault/users?role=Admin&region=US-East`

**Response:**
```json
{
  "total_users": 200,
  "global_rotation_count": 5,
  "users": [
    {
      "user_id": "USR-0001",
      "role": "Developer",
      "home_region": "EU-Central",
      "db_password": "x7Qm****!pR4",
      "api_key": "hpe_3f8a****",
      "service_token": "b2c4e8f1****",
      "rotation_count": 0,
      "status": "active",
      "created_at": "2026-04-24T17:00:00Z",
      "last_rotation_reason": "initial_provisioning"
    },
    {
      "user_id": "USR-0002",
      "role": "Finance",
      "home_region": "Asia-Pacific",
      "rotation_count": 2,
      "status": "rotated",
      "last_rotation_reason": "threat_detected_score_0.8745"
    }
  ]
}
```

---

### `GET /api/vault/users/{user_id}`
Returns masked credentials for a **single specific user**.

**Example:** `GET /api/vault/users/USR-0042`

**Response:**
```json
{
  "user_id": "USR-0042",
  "role": "Admin",
  "home_region": "US-West",
  "db_password": "kL9p****#mN2",
  "api_key": "hpe_7d2e****",
  "service_token": "a1b2c3d4****",
  "rotation_count": 1,
  "status": "rotated",
  "created_at": "2026-04-24T17:25:00Z",
  "last_rotation_reason": "threat_detected_score_0.9100",
  "triggered_by_threat_score": 0.91
}
```

---

## WebSocket

### `WS /ws/simulate`
Streams test events through the full pipeline in real-time.

**Connection:** `ws://localhost:8000/ws/simulate`

**Messages received (in order):**

1. **Server info:**
```json
{ "type": "server_info", "data": { "lat": 12.97, "lng": 77.59, "city": "Bangalore" } }
```

2. **Simulation status:**
```json
{ "type": "simulation_status", "data": { "resuming_from": 42, "total_events": 3500 } }
```

3. **Pipeline results (continuous):**
```json
{
  "type": "pipeline_result",
  "data": {
    "event": { "user_id": "USR-0042", "action": "file_download", ... },
    "prediction": {
      "event_id": "a1b2c3d4e5f6",
      "is_threat": true,
      "threat_score": 0.923,
      "threat_action": "CRITICAL_ALERT",
      "pipeline_stages": [ ... ]
    }
  }
}
```

---

## Authentication Endpoints

### `POST /api/auth/login`
Authenticate user and obtain session credentials.

**Request Body:**
```json
{
  "username": "alice",
  "password": "password123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "department": "Engineering",
  "user_id": "alice",
  "role": "Developer",
  "failed_attempts": 0,
  "last_login": "2026-06-20T10:30:00Z",
  "last_login_region": "US-East",
  "credentials_rotated": false
}
```

---

### `POST /api/auth/register`
Submit new user registration request (requires admin approval).

**Request Body:**
```json
{
  "username": "newuser",
  "department": "Finance"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Access request submitted. Awaiting admin approval and credential issuance."
}
```

---

### `POST /api/auth/simulate`
Process threat simulation event through the pipeline.

**Request Body:** (NetworkEvent with optional overrides)
```json
{
  "username": "alice",
  "password": "password123",
  "login_hour": 3,
  "ip_region": "EU-Central",
  "data_downloaded_mb": 500.0,
  "failed_attempts": 6,
  "impossible_travel": true,
  "is_vpn": true
}
```

---

## Admin Dashboard Endpoints

All admin endpoints require JWT authentication. Include the token in the `Authorization: Bearer <token>` header.

### `POST /api/admin/login`
Authenticate admin user and obtain JWT token.

**Request Body:**
```json
{
  "username": "admin",
  "password": "admin"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 1800,
  "username": "admin"
}
```

---

### `GET /api/admin/alerts`
Retrieve threat alerts with optional filtering.

**Query Parameters:**
- `status` (optional): Filter by status (`pending`, `approved`, `rejected`)
- `severity` (optional): Filter by severity
- `limit` (optional): Maximum alerts to return (default: 100)

**Response:**
```json
{
  "total": 42,
  "pending_count": 5,
  "alerts": [...]
}
```

---

### `GET /api/admin/alerts/{alert_id}`
Get detailed information for a specific alert.

---

### `POST /api/admin/alerts/{alert_id}/approve`
Approve credential rotation for a threat alert.

**Request Body:**
```json
{
  "admin_notes": "Confirmed malicious activity from VPN exit node"
}
```

---

### `POST /api/admin/alerts/{alert_id}/reject`
Reject alert as false positive.

---

### `GET /api/admin/stats`
Retrieve admin dashboard statistics.

---

### `GET /api/admin/audit-log`
Fetch admin action audit trail (append-only log).

**Query Parameters:**
- `limit` (optional): Maximum entries to return (default: 50)

---

### `GET /api/admin/registrations`
List pending user registration requests.

---

### `POST /api/admin/registrations/{username}/approve`
Approve user registration and provision credentials.

**Request Body:**
```json
{
  "password": "SecurePassword123!"
}
```

---

### `POST /api/admin/registrations/{username}/reject`
Reject and delete pending registration request.

---

### `POST /api/admin/reset/request`
Request pipeline reset (Step 1: Generate confirmation token).

**Response:**
```json
{
  "confirm_token": "a1b2c3d4...",
  "expires_in": 60,
  "message": "Send this token to POST /api/admin/reset/confirm within 60 seconds."
}
```

---

### `POST /api/admin/reset/confirm`
Execute pipeline reset with confirmation token (Step 2).

**Request Body:**
```json
{
  "confirm_token": "a1b2c3d4..."
}
```

**Note:** Reset preserves audit log and Kafka topics while wiping all derived state.

---

### `WS /api/admin/ws?token=<jwt_token>`
WebSocket connection for real-time admin notifications.

---

## External Service UIs

| Service | URL | Authentication |
|---|---|---|
| **Dashboard** | `http://localhost:5173` | None required |
| **Enterprise Portal** | `http://localhost:8080` | User credentials |
| **Vault UI** | `http://localhost:8200` | Token: `hpe-dev-token` |
| **Kibana** | `http://localhost:5601` | None required |
| **Adminer (DB)** | `http://localhost:9090` | postgres/vault-root/vault-root-secret |
| **Swagger Docs** | `http://localhost:8000/docs` | Interactive API documentation |
