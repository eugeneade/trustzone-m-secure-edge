# TrustZone-M Secure Edge Prototype

**Status: M1–M3 complete**

How much does hardware-enforced isolation cost on a real-time embedded processor?
This project builds a small secure communication service on an ARM Cortex-M33 with
TrustZone-M and measures the latency of moving security functions (key storage, message
authentication) into the hardware-isolated Secure world.

It is a first step toward my research interest: hardware-software co-design for secure,
trustworthy communication in autonomous edge systems, specifically, which security
responsibilities belong in hardware, which in software, and what each choice costs in
latency and resources.

## Platform
- ST NUCLEO-L552ZE-Q (STM32L552ZE, Cortex-M33, TrustZone-M), 110 MHz, instruction cache on
- C, GCC 14.3 and GNU Make (both bundled with STM32CubeIDE 2.2), STM32CubeProgrammer CLI
- mbedTLS 3.6.7 (SHA-256 only), CMSIS headers from ST
- PowerShell capture and summary script for measurements

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

The Secure image boots first, sets the security partition, then starts the Non-Secure
application. The application reaches the Secure world only through Non-Secure Callable
(NSC) entry points:

| Entry point | Purpose |
|-------------|---------|
| `SECURE_MAC_Compute` | HMAC-SHA256 of a message with the device key |
| `SECURE_MAC_Verify` | Constant-time check of a MAC |
| `SECURE_CryptoSelfTest` | RFC 4231 known-answer tests (cases 1, 2, 6) |
| `SECURE_Nop` | Empty call, used to time the bare world switch |
| `SECURE_Add`, `SECURE_GetCallCount` | M1 round-trip checks |

Every buffer passed in by the Non-Secure application is checked with
`cmse_check_address_range` before use. Without that check the application could make the
Secure service read or overwrite Secure memory on its behalf (a "confused deputy").

### Memory map
| Region | Address range | World |
|--------|---------------|-------|
| Flash bank 1 (code, device key) | `0x0C000000`–`0x0C03DFFF` | Secure |
| NSC veneers | `0x0C03E000`–`0x0C03FFFF` | Secure, callable from NS |
| Flash bank 2 | `0x08040000`–`0x0807FFFF` | Non-Secure |
| SRAM1 lower 96 KB | `0x30000000`–`0x30017FFF` | Secure |
| SRAM1 upper 96 KB + SRAM2 | `0x20018000`–`0x2003FFFF` | Non-Secure |

Enforced by the SAU (CPU side), GTZC block-based SRAM protection, flash secure
watermarks (option bytes) and GPIO pin security.

## Milestones
| # | Milestone | Status |
|---|-----------|--------|
| M1 | Hello TrustZone: Non-Secure app calls a Secure function | Done |
| M2 | Secure crypto service: key isolated in Secure world | Done |
| M3 | Measure Secure-call and crypto overhead (cycles, us) | Done |

**M2 verification on the board:** all functional checks pass (self-test, MAC accepted,
tampered message and tampered MAC rejected, Secure pointers refused). The device MAC was
cross-checked against .NET `HMACSHA256` on the host. With `make ISOLATION_TEST=1 flash`
the Non-Secure app reads Secure flash directly. The hardware blocks the read and raises a
SecureFault (`SFSR=0x48`, attribution unit violation, `SFAR=0x0C000000`).

## Results
SYSCLK 110 MHz, instruction cache on, GCC `-O2`. Each row: 1000 timed runs after 10
warm-up runs, interrupts masked, DWT cycle counter. Two independent runs gave identical
results (`results/m3_20261011_*.csv`).

| Operation | Bytes | Median cycles | Median us | Min | Max | Runs |
|-----------|------:|--------------:|----------:|----:|----:|-----:|
| Timer read only | 0 | 1 | 0.009 | 1 | 1 | 1000 |
| Empty call, Non-Secure | 0 | 7 | 0.064 | 7 | 11 | 1000 |
| Empty call, Non-Secure to Secure | 0 | 45 | 0.409 | 45 | 49 | 1000 |
| HMAC-SHA256 in Non-Secure | 16 | 26948 | 244.98 | 26948 | 26952 | 1000 |
| HMAC-SHA256 via Secure service | 16 | 27587 | 250.79 | 27587 | 27588 | 1000 |
| HMAC-SHA256 in Non-Secure | 64 | 32144 | 292.22 | 32144 | 32144 | 1000 |
| HMAC-SHA256 via Secure service | 64 | 32783 | 298.03 | 32783 | 32784 | 1000 |
| HMAC-SHA256 in Non-Secure | 256 | 47669 | 433.35 | 47669 | 47669 | 1000 |
| HMAC-SHA256 via Secure service | 256 | 48308 | 439.16 | 48308 | 48309 | 1000 |
| HMAC-SHA256 in Non-Secure | 1024 | 109769 | 997.90 | 109769 | 109769 | 1000 |
| HMAC-SHA256 via Secure service | 1024 | 110408 | 1003.71 | 110408 | 110409 | 1000 |

**Derived cost of the Secure world**

| Quantity | Cycles | us | Share of HMAC time |
|----------|-------:|---:|-------------------:|
| World switch (empty Secure call minus empty Non-Secure call) | 38 | 0.35 | |
| Secure MAC service minus same HMAC in Non-Secure, 16 B | 639 | 5.81 | 2.4% |
| Same, 64 B | 639 | 5.81 | 2.0% |
| Same, 256 B | 639 | 5.81 | 1.3% |
| Same, 1024 B | 639 | 5.81 | 0.6% |

**Findings so far**
- The world switch itself is cheap: 38 extra cycles (0.35 us) for a round trip into the
  Secure world and back.
- Running HMAC in the Secure service costs a fixed 639 cycles (5.8 us) more than the same
  code in the Non-Secure world, at every message size. The overhead is per call, not per
  byte, so its share shrinks as messages grow: 2.4% at 16 B, 0.6% at 1 KB.
- About 600 of those 639 cycles are not the world switch. They come from the service's
  own work around the HMAC, such as pointer validation, copying the tag out through a
  Secure buffer and zeroizing it, and possibly code placement. That cost has not been
  broken down yet.
- The SHA-256 computation dominates: about 81 cycles per extra byte in software, against a
  639-cycle fixed overhead for isolation. That points to hardware crypto acceleration as
  the bigger lever, not the isolation.

**Method notes and caveats**
- Each operation runs through the same function-pointer harness, and each wrapper makes
  exactly one further call. That way, both sides of every difference have the same call
  depth. Cycles are reported raw, without subtracting the 1-cycle timer cost.
- The DWT cycle counter counts in Secure state only while Secure non-invasive debug is
  allowed, which is true at RDP level 0. The Secure HMAC rows confirm that it counted
  inside the Secure world. At higher RDP levels this method would need a hardware timer
  instead.
- Results are warm-cache, steady-state numbers. Cold-start latency is not measured.
- The device key is a demo key compiled into Secure flash. A production device would
  provision a separate key into each unit at manufacture.
- The two images must always be flashed together, because the NSC entry-point addresses
  change when the Secure API changes. `make flash` does this.

## Build and run
Prerequisites: STM32CubeIDE 2.2 (provides GCC, make and STM32CubeProgrammer), a
NUCLEO-L552ZE-Q board, and Git Bash.

```sh
git clone --recursive git@github.com:eugeneade/trustzone-m-secure-edge.git
```

One-time board setup: enable TrustZone, keep flash bank 1 Secure and make bank 2
Non-Secure. Turning TrustZone off again requires an RDP regression, which mass-erases the
flash.

```powershell
$cli = 'C:\ST\STM32CubeIDE_2.2.0\STM32CubeIDE\plugins\com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.win32_2.2.500.202603051304\tools\bin\STM32_Programmer_CLI.exe'
& $cli -c port=SWD mode=UR -ob TZEN=1
& $cli -c port=SWD mode=UR -ob SECWM1_PSTRT=0x0 SECWM1_PEND=0x7F SECWM2_PSTRT=0x7F SECWM2_PEND=0x0
```

Build, flash, and capture a benchmark run. The make executable is in the CubeIDE
`...externaltools.make...` plugin folder. Adjust `CUBEIDE_PLUGINS` in the `Makefile` if
CubeIDE is installed elsewhere.

```sh
make                       # build build/secure.elf and build/nonsecure.elf
powershell -ExecutionPolicy Bypass -File results/capture.ps1 -Port COM5   # start first
make flash                 # program both images and reset; output on COM5, 115200 8N1
make ISOLATION_TEST=1 flash   # optional: show a direct NS read of Secure flash is blocked
```

`capture.ps1` saves the transcript to `results/raw/`, the CSV to `results/`, and a
Markdown summary with the derived overheads.

## Repository layout
- `Secure/` Secure-world firmware: partition setup, clocks, crypto service, NSC API (`Inc/secure_nsc.h`)
- `NonSecure/` Non-Secure application: functional checks and the M3 benchmark
- `Common/` HMAC-SHA256 and mbedTLS configuration, built into both images
- `third_party/` Git submodules: CMSIS device and core headers, mbedTLS
- `results/` Benchmark CSVs and summaries, raw UART logs, capture script
- `docs/` Milestone notes and write-ups

## Next steps
- Break down the fixed 639-cycle cost of the Secure MAC service: pointer checks, copy-out
  and zeroization, code placement.
- Compare with the STM32L5 hardware HASH accelerator, to weigh isolation cost against
  acceleration gain.
- Measure cold-cache, first-call latency.

## Author
Eugene Olowofela, P.Eng
