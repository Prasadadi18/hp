param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("start","stop","status")]
    [string]$Action,

    [int]$Pods = 5
)

$NAMESPACE = "hpe"
$PAYLOAD   = '{"src_ip":"10.0.0.1","dst_ip":"192.168.1.1","proto":"tcp","duration":2.5,"orig_bytes":2048,"resp_bytes":1024,"orig_pkts":20,"resp_pkts":15}'

switch ($Action) {

    "start" {
        Write-Host "`n[START] Launching $Pods load-gen pod(s) in namespace '$NAMESPACE'..." -ForegroundColor Green

        # Remove any existing load-gen pods first
        for ($i = 1; $i -le $Pods; $i++) {
            kubectl delete pod "load-gen$i" -n $NAMESPACE --ignore-not-found 2>$null | Out-Null
        }

        Start-Sleep -Seconds 2

        for ($i = 1; $i -le $Pods; $i++) {
            kubectl run "load-gen$i" `
                --image=hpe-backend:v2 `
                --restart=Never `
                -n $NAMESPACE `
                -- sh -c "while true; do curl -sf -X POST http://backend:8000/api/predict -H 'Content-Type: application/json' -d '$PAYLOAD' -o /dev/null; curl -sf http://backend:8000/api/elasticsearch/stats -o /dev/null; done" | Out-Null
            Write-Host "  [OK] load-gen$i created" -ForegroundColor Cyan
        }

        Write-Host "`n[INFO] Watch scaling:" -ForegroundColor Yellow
        Write-Host "   kubectl get hpa -n $NAMESPACE -w" -ForegroundColor Gray
        Write-Host "   kubectl top pods -n $NAMESPACE" -ForegroundColor Gray
    }

    "stop" {
        Write-Host "`n[STOP] Removing all load-gen pods in namespace '$NAMESPACE'..." -ForegroundColor Red

        $podList = kubectl get pods -n $NAMESPACE --no-headers -o custom-columns="NAME:.metadata.name" 2>$null |
                   Where-Object { $_ -match "^load-gen" }

        if ($podList) {
            foreach ($pod in $podList) {
                kubectl delete pod $pod -n $NAMESPACE --ignore-not-found | Out-Null
                Write-Host "  [OK] Deleted: $pod" -ForegroundColor Cyan
            }
            Write-Host "`n[INFO] HPA will scale DOWN after ~120s stabilization window." -ForegroundColor Yellow
        } else {
            Write-Host "  [INFO] No load-gen pods found." -ForegroundColor Gray
        }
    }

    "status" {
        Write-Host "`n[HPA Status]" -ForegroundColor Yellow
        kubectl get hpa -n $NAMESPACE

        Write-Host "`n[Load-gen pods]" -ForegroundColor Yellow
        $podList = kubectl get pods -n $NAMESPACE --no-headers | Select-String "load-gen"
        if ($podList) { $podList } else { Write-Host "  None running." -ForegroundColor Gray }

        Write-Host "`n[Backend CPU]" -ForegroundColor Yellow
        kubectl top pods -n $NAMESPACE -l app=backend 2>$null
    }
}
