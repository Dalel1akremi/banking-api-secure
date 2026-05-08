# Script d'Analyse de Securite (OWASP ZAP)
$ReportPath = "$PSScriptRoot\..\documentation"
$NetworkName = "banking-api-secure_backend_tier"
$TargetURL = "http://banking_backend:8000"

Write-Host "--- Lancement du scan OWASP ZAP ---" -ForegroundColor Cyan

# 1. Verifier le dossier documentation
if (-not (Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath
}

# 2. Lancer le scan via Docker
Write-Host "Execution du scan (Docker)..." -ForegroundColor Yellow

docker run --rm `
    --network $NetworkName `
    -v "$($ReportPath):/zap/wrk/:rw" `
    ghcr.io/zaproxy/zaproxy:stable `
    zap-baseline.py -t $TargetURL -r zap_report.html

if ($LASTEXITCODE -eq 0) {
    Write-Host "SUCCESS: Scan termine." -ForegroundColor Green
    Write-Host "Rapport disponible: documentation\zap_report.html" -ForegroundColor Green
} else {
    Write-Host "WARNING: Scan termine avec des alertes." -ForegroundColor Yellow
    Write-Host "Rapport disponible: documentation\zap_report.html" -ForegroundColor Green
}
