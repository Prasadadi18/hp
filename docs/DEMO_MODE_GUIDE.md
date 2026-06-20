# Demo Mode vs Production Mode — Automated Credential Rotation

## Overview

The AI-Based Network Monitoring and Anomaly Detection System supports two credential rotation modes to accommodate different deployment scenarios. The **automated user credential rotation** feature can be toggled between **Demo Mode** (for testing/presentations) and **Production Mode** (for real-world deployments) using the `ENABLE_AUTO_USER_ROTATION` environment variable.

**Key Distinction:**
- **Demo Mode:** User credentials rotate only after admin approval (easier testing and demonstrations)
- **Production Mode:** User credentials rotate automatically on threat detection (enterprise security best practice)
- **Infrastructure Rotation:** Always requires admin approval in both modes (database, Kafka credentials)

---

## 🎭 Demo Mode (Default)

**When to use:** Demos, testing, development, presentations

**Setting:** `ENABLE_AUTO_USER_ROTATION=false` (or omit the variable)

### Behavior:
- ✅ User credentials **DO NOT** rotate automatically on threat detection
- ✅ User credentials rotate **ONLY** after admin approval
- ✅ Same test credentials can be used repeatedly
- ✅ Easy to demonstrate "before and after" admin approval workflow

### Use Case:
```bash
# Tester logs in as USR-0080 with password "demo123"
# Threat detected → Alert created → NO credential change yet
# Tester can try again as USR-0080 with same password
# Admin approves alert → NOW credentials rotate
```

**Perfect for:**
- Live demonstrations with predictable behavior
- Multiple test scenarios with consistent credentials  
- Training and educational sessions
- Development and debugging environments

---

## 🚀 Production Mode (Enterprise Deployment)

**When to use:** Production deployments, real-world security operations, enterprise SOC environments

**Setting:** `ENABLE_AUTO_USER_ROTATION=true`

### Behavior:
- ⚡ User credentials rotate **IMMEDIATELY** on BLOCK/CRITICAL detection (milliseconds)
- ⚡ Infrastructure credentials rotate **ONLY** after admin approval (CRITICAL only)
- 🛡️ Aligns with enterprise SOAR best practices
- 📊 Complete audit trail for automatic rotations

### Use Case:
```bash
# Real user account compromised
# Threat detected → User credentials rotated INSTANTLY (attacker locked out)
# Admin reviews alert → Approves infrastructure rotation if CRITICAL
```

**Perfect for:**
- Production security operations
- Real threat detection systems
- Enterprise deployments
- Compliance requirements

---

## Configuration Examples

### Docker Compose

Edit `docker-compose.yml` or `docker-compose.portal.yml`:

```yaml
backend:
  environment:
    # Demo mode (default) — credentials stable for testing
    - ENABLE_AUTO_USER_ROTATION=false
    
    # Production mode — immediate automatic rotation
    # - ENABLE_AUTO_USER_ROTATION=true
```

### Environment Variable

For local development or custom deployments:

```bash
# Demo mode
export ENABLE_AUTO_USER_ROTATION=false

# Production mode
export ENABLE_AUTO_USER_ROTATION=true
```

### Kubernetes Deployment

For Kubernetes deployments, update the backend ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: backend-config
  namespace: hpe
data:
  ENABLE_AUTO_USER_ROTATION: "false"  # Demo mode
  # ENABLE_AUTO_USER_ROTATION: "true"   # Production mode
```

Then restart backend pods:
```bash
kubectl rollout restart deployment/backend -n hpe
```

### Restart Application

```bash
# Docker Compose
docker-compose restart backend

# Kubernetes
kubectl rollout restart deployment/backend -n hpe
```

---

## Comparison Table

| Feature                        | Demo Mode (false)                | Production Mode (true)           |
|--------------------------------|----------------------------------|----------------------------------|
| **User rotation timing**       | After admin approval             | Immediate on detection           |
| **Credential stability**       | Stable (great for testing)       | Changes on every threat          |
| **Response time**              | Minutes (human approval)         | Milliseconds (automated)         |
| **Infrastructure rotation**    | After admin approval (CRITICAL)  | After admin approval (CRITICAL)  |
| **Best for**                   | Demos, testing, development      | Production, real security ops    |
| **Test repeatability**         | ✅ High                          | ❌ Low (creds keep changing)     |
| **Security response speed**    | ⏰ Delayed                       | ⚡ Instant                       |

---

## Admin Dashboard Messages

### Demo Mode:
```
"User credentials for USR-0080 rotated successfully (demo mode)."
```

### Production Mode:
```
"User credentials for USR-0080 were already rotated automatically at threat detection."
```

---

## Testing Both Modes

### Test Demo Mode:
```bash
# Set demo mode
export ENABLE_AUTO_USER_ROTATION=false
docker-compose restart backend

# Start simulation
curl -X POST http://localhost:8000/api/simulate/start

# Credentials await admin approval in admin dashboard
```

### Test Production Mode:
```bash
# Set production mode
export ENABLE_AUTO_USER_ROTATION=true
docker-compose restart backend

# Start simulation
curl -X POST http://localhost:8000/api/simulate/start

# Credentials rotate automatically on threat detection
```

---

## Logs to Watch

### Demo Mode Logs:
```
[hpe.threat_engine] Stage 7: status=pending_admin_approval
[hpe.threat_engine] Stage 8: status=pending_user_rotation (demo mode)
[ADMIN] User credential rotation for USR-0080 (mode=demo, action=BLOCK)
```

### Production Mode Logs:
```
[AUTO-ROTATION] User credentials rotated automatically for USR-0080 (threat=BLOCK, score=0.7842, success=True)
[ADMIN] User credentials for USR-0080 were already rotated automatically at detection
```
