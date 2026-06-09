# Demo Mode vs Production Mode

## Overview

The automated user credential rotation feature can be toggled between **Demo Mode** (for testing/presentations) and **Production Mode** (for real deployments) using the `ENABLE_AUTO_USER_ROTATION` environment variable.

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
- Live demos where you need predictable credentials
- Testing multiple scenarios with the same user
- Training sessions
- Development environments

---

## 🚀 Production Mode

**When to use:** Production deployments, enterprise security operations

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

## Configuration

### Docker Compose

Edit `docker-compose.yml`:

```yaml
backend:
  environment:
    # Demo mode (default) — credentials stable for testing
    - ENABLE_AUTO_USER_ROTATION=false
    
    # Production mode — immediate automatic rotation
    # - ENABLE_AUTO_USER_ROTATION=true
```

### Environment Variable

```bash
# Demo mode
export ENABLE_AUTO_USER_ROTATION=false

# Production mode
export ENABLE_AUTO_USER_ROTATION=true
```

### Restart Application

```bash
docker-compose restart backend
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

# Check logs — should see "pending_admin_approval"
docker logs hpe-backend | grep -i "user_rotation"

# Approve alert in admin dashboard
# NOW credentials rotate
```

### Test Production Mode:
```bash
# Set production mode
export ENABLE_AUTO_USER_ROTATION=true
docker-compose restart backend

# Start simulation
curl -X POST http://localhost:8000/api/simulate/start

# Check logs — should see "[AUTO-ROTATION]" immediately
docker logs hpe-backend | grep "AUTO-ROTATION"

# Credentials already rotated before admin sees the alert!
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

---

## Recommendation

- **Use Demo Mode** for your internship presentation and testing
- **Explain both modes** in your documentation (shows you understand production vs testing needs)
- **Demonstrate the toggle** to show enterprise-ready design

---

## Questions?

**Q: Will this break my existing demos?**  
A: No! Demo mode (default) preserves the original behavior where credentials rotate only after admin approval.

**Q: Do I need to change anything in my code?**  
A: No code changes needed. Just set the environment variable.

**Q: What's the default if I don't set anything?**  
A: Demo mode (ENABLE_AUTO_USER_ROTATION=false) — safe for testing!

**Q: Can I switch between modes without rebuilding?**  
A: Yes! Just change the environment variable and restart: `docker-compose restart backend`
