@{
    # Schema version for forward compatibility
    # 2.0.0: Module entries are hashtables with Path + metadata (Prefix, Deferred, GlobalForce)
    SchemaVersion = "2.0.0"

    # Core files - always required, not modules (entry points and data)
    CoreFiles = @(
        "Win11Config.ps1"
        "src/Win11Config.App.ps1"
        "src/VERSION.psd1"
        "src/RUNTIME_DEPENDENCIES.psd1"
        "src/Manifest/WinConfig.Tools.psd1"   # Tool registry with Dry Run declarations
    )

    # Modules that MUST load successfully - application fails without these
    # Order IS load order. Dependencies must be listed before dependents.
    RequiredModules = @(
        @{ Path = "src/Modules/ModuleLoader.psm1" }          # Bootstrap-preloaded, verified only
        @{ Path = "src/Modules/Paths.psm1" }                 # MUST load first: ephemeral temp root
        @{ Path = "src/Modules/ExecutionIntent.psm1" }       # Safety gate: mutation guards
        @{ Path = "src/Modules/DiagnosticTypes.psm1"         # Type system: closed enum constants
           GlobalForce = $true }                              # Double-import for WinForms runspace
        @{ Path = "src/Modules/Console.psm1"                 # Diagnostic output formatting
           Prefix = "WinConfig" }
        @{ Path = "src/Modules/Env.psm1" }                   # System info: admin check, machine info
        @{ Path = "src/Modules/UiAction.psm1" }              # CONTRACT-001: delegate wrappers
        @{ Path = "src/Modules/StagingAssertions.psm1" }     # Phase 11 tripwires
    )

    # Modules that gracefully degrade if missing - warning only
    # Order IS load order. Deferred modules are NOT loaded at startup.
    OptionalModules = @(
        @{ Path = "src/Logging/Logger.psm1"                  # JSONL session logging
           Prefix = "WinConfig" }
        @{ Path = "src/Modules/SessionOperationLedger.psm1"  # Operation tracking for PPF
           Prefix = "WinConfig" }
        @{ Path = "src/Modules/PpfFingerprint.psm1"          # Problem Pattern Fingerprinting
           Prefix = "WinConfig" }
        @{ Path = "src/Modules/ActionTiers.psm1"             # Tier recommendations
           Prefix = "WinConfig" }
        @{ Path = "src/Modules/ToolAsync.psm1"               # Async tool execution
           Prefix = "WinConfig" }
        @{ Path = "src/Modules/DryRun.psm1"                  # Dry Run infrastructure
           Prefix = "WinConfig" }
        @{ Path = "src/Modules/Bluetooth.psm1"               # BT audio diagnostics (PERF-001)
           Prefix = "WinConfig"
           Deferred = $true }                                 # Lazy-loaded on first Bluetooth tab use
    )

    # Documentation of invariants (for governance reference)
    # Enforced by: RuntimeDependencies.Completeness.Tests.ps1, publish-dist.yml
    Invariants = @(
        "Every RequiredModule MUST exist in Bootstrap.ps1 FileManifests"
        "Every manifest file MUST be in CoreFiles, RequiredModules, or OptionalModules"
        "No module may appear in both RequiredModules and OptionalModules"
        "CoreFiles are not Import-Module targets"
        "Manifest order IS load order"
    )
}
