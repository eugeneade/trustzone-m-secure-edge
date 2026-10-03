# TrustZone-M Secure Edge Prototype

**Status: in progress**

How much does hardware-enforced isolation cost on a real-time embedded processor?
This project builds a small secure communication service on an ARM Cortex-M33 with
TrustZone-M and measures the latency of moving security functions (key storage, message
authentication) into the hardware-isolated Secure world.

It is a first step toward my research interest: hardware-software co-design for secure,
trustworthy communication in autonomous edge systems, specifically, which security
responsibilities belong in hardware, which in software, and what each choice costs in
latency and resources.

## Platform
- ST NUCLEO-L552ZE-Q (STM32L552ZE, Cortex-M33, TrustZone-M)
- STM32CubeIDE, C, mbedTLS / ST crypto library
- Python for measurement analysis

## Design
```
 Non-Secure world                       Secure world
 ┌──────────────────────┐   NSC call   ┌──────────────────────────┐
 │ Application          │ ───────────▶ │ Crypto service           │
 │ (sends messages,     │              │ - device key (never      │
 │  never sees the key) │ ◀─────────── │   leaves Secure world)   │
 └──────────────────────┘   MAC/sig    │ - HMAC / signing         │
                                       └──────────────────────────┘
```

## Milestones
| # | Milestone | Status |
|---|-----------|--------|
| M1 | Hello TrustZone: Non-Secure app calls a Secure function | Not started |
| M2 | Secure crypto service: key isolated in Secure world | Not started |
| M3 | Measure Secure-call and crypto overhead (cycles, us) | Not started |

## Results
_Measurements will appear here after M3._

| Operation | Mean cycles | Mean us | Min | Max | Runs |
|-----------|-------------|---------|-----|-----|------|
| | | | | | |

## Repository layout
- `Secure/` Secure-world firmware
- `NonSecure/` Non-Secure application
- `docs/` Milestone notes and write-ups
- `results/` Raw data and analysis scripts

## Author
Eugene Olowofela, P.Eng
