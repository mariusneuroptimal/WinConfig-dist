# Run-DISMRestoreHealth.ps1 - DISM system image repair payload
# Called via Invoke-DiagnosticConsole.ps1 wrapper

Write-Diagnostic INFO "Starting DISM Restore Health operation..."
Write-Diagnostic INFO "This may take 15-30 minutes depending on system state."
Write-ConsoleSeparator

DISM /Online /Cleanup-Image /RestoreHealth

Write-Host ""
Write-ConsoleSeparator
if ($LASTEXITCODE -eq 0) {
    Write-Diagnostic OK "DISM completed successfully."
} else {
    Write-Diagnostic WARN "DISM completed with exit code: $LASTEXITCODE"
}
