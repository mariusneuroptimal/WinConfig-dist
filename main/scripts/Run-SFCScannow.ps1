# Run-SFCScannow.ps1 - System File Checker payload
# Called via Invoke-DiagnosticConsole.ps1 wrapper

Write-Diagnostic INFO "Starting System File Checker (SFC) scan..."
Write-Diagnostic INFO "This may take 10-20 minutes depending on system state."
Write-ConsoleSeparator

sfc /scannow

Write-Host ""
Write-ConsoleSeparator
if ($LASTEXITCODE -eq 0) {
    Write-Diagnostic OK "SFC completed successfully."
} else {
    Write-Diagnostic WARN "SFC completed with exit code: $LASTEXITCODE"
}
