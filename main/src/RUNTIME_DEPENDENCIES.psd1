@{
    # Schema version for forward compatibility
    SchemaVersion = "1.0.0"

    # Core files - always required, not modules (entry points and data)
    CoreFiles = @(
        "Win11Config.ps1"
        "src/Win11Config.App.ps1"
        "src/VERSION.psd1"
        "src/RUNTIME_DEPENDENCIES.psd1"
    )

    # Modules that MUST load successfully - bootstrap fails if any missing/corrupt
    # Order matters: dependencies must be listed before dependents
    RequiredModules = @(
        "src/Modules/ModuleLoader.psm1"       # Execution-critical: loads other modules
        "src/Modules/ExecutionIntent.psm1"    # Safety gate: mutation guards
        "src/Modules/Console.psm1"            # Required UI: diagnostic output formatting
        "src/Modules/Env.psm1"                # System info: admin check, machine info
        "src/Modules/Paths.psm1"              # Directory constants
        "src/Modules/DiagnosticTypes.psm1"    # Type system: closed enum constants, Switch-DiagnosticResult
        "src/Modules/UiAction.psm1"           # CONTRACT-001: self-bootstrapping delegate wrappers
    )

    # Modules that gracefully degrade if missing - warning only
    OptionalModules = @(
        "src/Logging/Logger.psm1"             # JSONL session logging
        "src/Modules/Bluetooth.psm1"          # BT audio diagnostics
        "src/Modules/ActionTiers.psm1"        # Tier recommendations
        "src/Modules/SessionOperationLedger.psm1"  # Operation tracking for PPF
        "src/Modules/PpfFingerprint.psm1"     # Problem Pattern Fingerprinting
    )

    # Documentation of invariants (for governance reference)
    # These are checked programmatically by Update-BootstrapManifest.ps1
    Invariants = @(
        "Every RequiredModule MUST exist in Bootstrap.ps1 FileManifests"
        "Every manifest file MUST be in CoreFiles, RequiredModules, or OptionalModules"
        "No module may appear in both RequiredModules and OptionalModules"
        "CoreFiles are not Import-Module targets"
    )
}
