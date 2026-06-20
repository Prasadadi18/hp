from app.db import execute_query
rows = execute_query("SELECT alert_id, threat_score, event_data->>'event_source' as src, threat_action FROM hpe_admin_alerts ORDER BY created_at DESC LIMIT 10")
for r in rows: print(r)
