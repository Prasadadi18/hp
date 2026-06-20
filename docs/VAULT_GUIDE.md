# HashiCorp Vault — Credential Security Architecture

> **Comprehensive credential management documentation.** This document explains the complete credential security architecture implemented in the AI-Based Network Monitoring and Anomaly Detection System, including HashiCorp Vault integration for user credential management, dynamic database secrets, AppRole authentication, and automated Kubernetes unsealing.

---

## Architecture Overview

```
user_profiles.json (200 users)
         │
         ▼ (on backend startup)
   vault_client.py
         │
         ▼
   HashiCorp Vault (Raft persistent storage)
   ┌──────────────────────────────────────────────────┐
   │  secret/hpe/users/USR-0001  ← db_password,      │
   │  secret/hpe/users/USR-0002    api_key,           │
   │  secret/hpe/users/USR-0003    service_token      │
   │  ...                                             │
   │  secret/hpe/users/USR-0200                      │
   │                                                  │
   │  database/creds/hpe-backend-role  ← dynamic     │
   │  database/creds/hpe-readonly-role   PostgreSQL   │
   │                                                  │
   │  auth/approle/role/hpe-backend    ← AppRole      │
   │  secret/hpe/kafka                 ← Kafka creds  │
   └──────────────────────────────────────────────────┘
         │
         ▼
   vault-data PVC (/vault/data)
   ├── .unseal_key          ← read by unseal-watcher sidecar
   ├── .root_token          ← used only during vault-init Job
   ├── .approle_credentials ← read by backend at startup
   ├── .initialized         ← first-boot flag
   ├── .db_engine_configured
   └── .approle_configured
```

---

## How It Works

### 1. Startup — Credential Seeding

When the backend starts (`main.py` → `vault_client.connect_vault()`):
1. Authenticates to Vault using AppRole (reads `role_id` and `secret_id` from shared PVC)
2. Reads all 200 user profiles from `user_profiles.json`
3. For each user, creates a Vault secret at `secret/hpe/users/{user_id}`
4. Each secret contains:
   - `db_password` — 32-character cryptographically secure password
   - `api_key` — Prefixed with `hpe_` + 48 hex characters
   - `service_token` — UUID v4
   - `role` — from profile (Developer, Admin, Finance, HR, Sales)
   - `home_region` — from profile (US-East, US-West, EU-Central, Asia-Pacific, South-America)
   - `rotation_count` — starts at 0
   - `status` — "active" initially
   - `last_rotation_reason` — "initial_provisioning"
   - `created_at` — ISO timestamp

### 2. Threat Detection — Automated User Rotation

The system supports two credential rotation modes controlled by the `ENABLE_AUTO_USER_ROTATION` environment variable:

**Production Mode** (`ENABLE_AUTO_USER_ROTATION=true`):
- User credentials rotate **automatically** when AI engine detects BLOCK or CRITICAL threats
- Rotation happens in milliseconds without admin approval
- Admin still reviews and approves infrastructure rotation for CRITICAL alerts

**Demo/Testing Mode** (`ENABLE_AUTO_USER_ROTATION=false`, default):
- User credentials rotate **only after admin approval**
- Allows repeated testing with same credentials
- Better for demonstrations and development

When rotation occurs:
1. `threat_engine.py` calls `vault_client.rotate_credentials(user=event.user_id)`
2. Only **that user's** credentials are regenerated
3. The secret at `secret/hpe/users/{user_id}` is updated with:
   - Brand new `db_password`, `api_key`, `service_token`
   - Incremented `rotation_count`
   - `status` → "rotated"
   - `last_rotation_reason` → `"threat_detected_score_0.XXXX"` or `"admin_approved_..."`
   - Updated `created_at` timestamp
4. New credentials are emailed to the security admin via `soar_email.py`

### 3. CRITICAL Alert — Infrastructure Rotation

When an admin approves a CRITICAL alert (threat score > 0.85), the system performs infrastructure credential rotation based on the affected service:

**Database Rotation** (data_exfiltration, bulk_download, admin actions):
1. `vault_infra_client.py` immediately revokes the active PostgreSQL dynamic credential lease
2. Vault generates a brand-new database user with time-limited access
3. Old database user ceases to exist within milliseconds

**Kafka Rotation** (lateral_movement, privilege_escalation):
1. `vault_infra_client.py` rotates Kafka credentials stored in Vault KV (`secret/hpe/kafka`)
2. `kafka_client.reconnect_kafka()` fetches new credentials and rebuilds producer/consumer clients
3. Zero downtime credential rotation with automatic reconnection

Both rotations are logged to the audit trail in PostgreSQL with admin attribution.

### 4. API Access — Viewing Credentials

| Endpoint | What you see |
|---|---|
| `/api/vault/users` | All 200 users, masked passwords |
| `/api/vault/users/USR-0042` | Single user detail |
| `/api/vault/credentials` | Latest rotated user (for dashboard) |
| Vault UI (`localhost:8200`) | Full unmasked values |

---

## Dynamic Database Credentials

The system uses Vault's database secrets engine to generate short-lived PostgreSQL credentials on demand. No static database password exists anywhere in the codebase.

| Role | TTL | Permissions |
|------|-----|-------------|
| `hpe-backend-role` | 1 hour | SELECT, INSERT, UPDATE on all tables |
| `hpe-readonly-role` | 30 minutes | SELECT only |

Vault automatically revokes these users when the lease expires. On a CRITICAL alert approval, `vault_infra_client.py` forcefully revokes the current lease immediately — the compromised database user ceases to exist within milliseconds.

---

## AppRole Authentication

The backend authenticates to Vault using AppRole rather than a static token. On startup, the backend reads a `role_id` and `secret_id` from the shared PVC (written by the vault-init Job) and exchanges them for a short-lived Vault token. A background thread auto-renews this token every 45 minutes. The root token is only used during the vault-init Job and is never visible to the running application.

**Credential file location** (written by vault-init, mounted read-only by backend):
```
/vault/data/.approle_credentials
```

---

## Kafka Credentials

Kafka broker credentials are stored in Vault KV at `secret/hpe/kafka` and fetched at backend startup via `vault_infra_client.py`. 

**Rotation Process:**
1. On `lateral_movement` or `privilege_escalation` CRITICAL alert approval
2. `vault_infra_client.py` rotates the Kafka credentials in Vault KV
3. `kafka_client.reconnect_kafka()` fetches the newly rotated credentials
4. All Kafka producer/consumer clients are rebuilt with new credentials
5. Zero downtime — reconnection happens automatically in the background

This ensures that compromised Kafka credentials can be invalidated instantly while maintaining pipeline continuity.

---

## Auto-Unseal on Kubernetes Restart

> **Why does Vault seal itself?**  
> Vault uses [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) as a security mechanism. When Vault's container restarts (e.g., after `kubectl rollout restart` or cluster maintenance), Vault deliberately seals itself. This is **by design** — if someone gains physical access to the server, they cannot read secrets without the unseal key.

**Automated Unsealing:**
The Vault StatefulSet in Kubernetes includes an `unseal-watcher` sidecar container that automatically handles unsealing:

**How It Works:**
1. Sidecar polls Vault's seal status every 15 seconds
2. When Vault is detected as sealed (after restart), it automatically calls the unseal API
3. No manual intervention required — Vault becomes operational automatically

**Security Features:**
- Sidecar mounts vault-data PVC as `readOnly: true` — can only read unseal key, never write
- Has no Vault token and cannot read or modify secret data
- Only has permission to call `/v1/sys/unseal` endpoint
- Runs under dedicated `vault-sa` ServiceAccount with least-privilege RBAC

**Monitoring:**
```bash
# Follow unseal-watcher logs in real time
kubectl logs vault-0 -c unseal-watcher -n hpe -f

# Expected output after a restart:
# [unseal-watcher] Vault is SEALED — attempting auto-unseal...
# [unseal-watcher] Vault unsealed successfully.

# Verify both containers are running
kubectl get pod vault-0 -n hpe -o jsonpath='{.status.containerStatuses[*].name}'
# Output: vault unseal-watcher
```

---

## Viewing in Vault UI

1. Open `http://localhost:8200`
2. Login method: **Token**
3. Token: `hpe-dev-token`
4. Navigate: **Secrets** → **secret/** → **hpe/** → **users/**
5. Click any user (e.g., `USR-0042`) to see full credentials

---

## User Roles Distribution

| Role | Count | Description |
|---|---|---|
| Developer | ~50 | High download volumes, varied hours |
| Sales | ~50 | Moderate activity, high travel probability |
| Finance | ~35 | Regular hours, low downloads |
| Admin | ~30 | High privileges, varied patterns |
| HR | ~20 | Regular hours, low volume |

*Note: Some users have `is_shift_worker: true` which gives them unusual login hours. These are NOT threats — the AI must learn to distinguish legitimate shift work from actual attacks.*

---

## Security Notes

- **Raft Persistent Storage:** Secrets survive container restarts. `docker-compose down -v` or `kubectl delete namespace hpe` wipes the PVC and resets Vault completely
- **Dynamic DB Credentials:** No static database passwords exist. Vault creates and revokes PostgreSQL users automatically on each request and on CRITICAL alert approvals
- **AppRole Authentication:** Root token only used during `vault-init`. Running backend only holds short-lived AppRole token that auto-renews every 45 minutes
- **Auto-Unseal Sidecar:** Uses `readOnly: true` PVC access and carries no Vault token — can only trigger unseal API, not read secrets
- **Masked API Responses:** `/api/vault/users` endpoint masks passwords (first 4 chars + `****` + last 4 chars). Full values only visible in Vault UI
- **KV v2 Versioning:** Vault KV v2 secrets engine provides versioning — full history of credential rotations available for each user
- **Email Notifications:** New credentials emailed to security admin via `soar_email.py` on rotation
- **Redis Caching:** User profile and VPN lookup results cached in Redis for performance (L1: in-process dict, L2: shared Redis)
- **JWT Admin Auth:** Admin console protected by JWT tokens stored in Vault at `hpe/admin-jwt`
- **Audit Trail:** All admin actions logged to append-only `hpe_admin_audit_log` table with admin attribution
