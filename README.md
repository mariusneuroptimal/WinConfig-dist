# WinConfig Distribution

This repository contains distribution artifacts for [WinConfig](https://github.com/mariusneuroptimal/WinConfig).

## Structure

```
├── main/           # Production artifacts
│   ├── manifest.json
│   └── ... (application files)
└── develop/        # Staging artifacts
    ├── manifest.json
    └── ... (application files)
```

## Usage

Bootstrap automatically fetches from this repository. No manual download needed.

## Security

- All files are SHA-256 verified against `manifest.json`
- Artifacts are published only after CI integrity checks pass
- Source repository is private; this repo contains only published artifacts

## Links

- Source: [WinConfig](https://github.com/mariusneuroptimal/WinConfig) (private)
- Documentation: Contact NeurOptimal support

---
*This repository is automatically updated by CI. Do not edit manually.*
