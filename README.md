# TrustZone-M Secure Edge Prototype

**Status: M1–M5 complete**

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
| `SECURE_Nop` | Empty call, used to time the bare world switch (M3) and world-switch interrupts (M5) |
| `SECURE_Add`, `SECURE_GetCallCount` | M1 round-trip checks |
| `SECURE_Probe_*` | M4 measurement-only probes (would be left out of a production build) |

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
| M4 | Explain the Secure-service overhead step by step, fix its largest cost | Done |
| M5 | Interrupt latency while the CPU runs Secure code | Done |

**M2 verification on the board:** all functional checks pass (self-test, MAC accepted,
tampered message and tampered MAC rejected, Secure pointers refused). The device MAC was
cross-checked against .NET `HMACSHA256` on the host. With `make ISOLATION_TEST=1 flash`
the Non-Secure app reads Secure flash directly. The hardware blocks the read and raises a
SecureFault (`SFSR=0x48`, attribution unit violation, `SFAR=0x0C000000`).

## Results
### M3: cost of the Secure world
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

**Derived cost of the Secure world** (M3 baseline, before the M4 fix)

| Quantity | Cycles | us | Share of HMAC time |
|----------|-------:|---:|-------------------:|
| World switch (empty Secure call minus empty Non-Secure call) | 38 | 0.35 | |
| Secure MAC service minus same HMAC in Non-Secure, 16 B | 639 | 5.81 | 2.4% |
| Same, 64 B | 639 | 5.81 | 2.0% |
| Same, 256 B | 639 | 5.81 | 1.3% |
| Same, 1024 B | 639 | 5.81 | 0.6% |

**M3 findings**
- The world switch itself is cheap: 38 extra cycles (0.35 us) for a round trip into the
  Secure world and back.
- Running HMAC in the Secure service cost a fixed 639 cycles (5.8 us) more than the same
  code in the Non-Secure world, at every message size. The overhead is per call, not per
  byte, so its share shrinks as messages grow: 2.4% at 16 B, 0.6% at 1 KB.
- About 600 of those 639 cycles were not the world switch. M4 explains them.
- The SHA-256 computation dominates: about 81 cycles per extra byte in software. That
  points to hardware crypto acceleration as the bigger lever, not the isolation.

### M4: where the Secure-service overhead goes
Each step of `SECURE_MAC_Compute` was timed with the cycle counter from inside the Secure
world, so the steps add up without cross-world call costs. The HMAC itself was also timed
from inside each world. Same settings as M3; two runs after the fix gave identical
results (`results/bench_20261031_165904.csv`, `results/bench_20261031_165941.csv`).
The before-fix run is `results/bench_20261031_165713.csv`.

| Step (64 B message, medians) | Before fix | After fix |
|------------------------------|-----------:|----------:|
| World switch (empty Secure call minus empty Non-Secure call) | 38 | 38 |
| Passing three arguments | 4 | 4 |
| Pointer checks (`cmse_check_address_range` ×2) | 93 | 96 |
| Copying the 32-byte tag out | 16 | 19 |
| Zeroizing the 32-byte tag | **250** | **35** |
| HMAC core, Secure minus Non-Secure | 1 | 8 |
| Sum of steps | 402 | 200 |
| **Measured total (Secure service minus same HMAC in Non-Secure)** | **404** | **226** |
| Unexplained residual | 2 | 26 |

The step costs are identical at 1024 B: none of them depends on message size.

**M4 findings**
- **The hardware isolation is a small part of the cost.** The world switch plus argument
  passing is 42 cycles. Before the fix, 62% of the overhead was zeroizing one 32-byte tag.
- **Cause:** `mbedtls_platform_zeroize` calls newlib-nano's size-optimized `memset`, which
  clears one byte per loop iteration (about 7.8 cycles per byte). Replacing it with a
  word-at-a-time volatile zeroize for the Secure service's tag buffers cut that step from
  249 to 35 cycles, measured in the same build. The end-to-end overhead fell from 404 to
  226 cycles (−44%), now 0.21–0.84% of the HMAC time.
- **The same HMAC code runs equally fast in both worlds.** Timed from inside each world,
  the HMAC core differs by 1–8 cycles out of 32,000+.
- **Pointer validation is now the largest step** at 96 cycles: two calls to the generic
  `cmse_check_address_range` library routine.
- **Code placement matters.** Between the M3 build and the first M4 build,
  `SECURE_MAC_Compute` did not change, yet its measured overhead moved from 639 to 404
  cycles because other code moved in flash. Step timings also shift by a few cycles
  between builds. Cross-build comparisons need that caveat; within-build comparisons (as
  used for the zeroize fix) are more reliable. The cause of the 235-cycle shift has not
  been isolated. The byte-wise `memset` loop is a plausible suspect.

### M5: interrupt latency while the CPU runs Secure code
A Non-Secure timer (TIM2) counts at the CPU clock and interrupts every 7,919 cycles, a
prime period so interrupts land at many points of the running code. The handler reads the
timer first, giving the cycles from the timer event to the handler. The DWT counter
confirmed the timer runs at the CPU clock: the measured period was 7,919 cycles. 1000
interrupts per row; two runs gave identical minimum, median and maximum values
(`results/bench_20261031_170707.csv`, `results/bench_20261031_170748.csv`).

| CPU was running | Median cycles | Max cycles | Max us | Max minus idle |
|-----------------|--------------:|-----------:|-------:|---------------:|
| Idle Non-Secure loop | 21 | 21 | 0.19 | 0 |
| HMAC-SHA256 (1 KB) in Non-Secure | 21 | 21 | 0.19 | 0 |
| HMAC-SHA256 (1 KB) inside the Secure service | 30 | 32 | 0.29 | +11 |
| Empty Secure calls back to back | 30 | 30 | 0.27 | +9 |

The 21-cycle baseline includes the handler prologue and the timer read, which are the
same in every row. Only the differences matter.

**M5 findings**
- **Secure code delays a Non-Secure interrupt by 9–11 cycles (0.1 us), not by the length
  of the Secure operation.** A 1 KB Secure HMAC takes about 1 ms, but an interrupt arriving
  during it is handled after at most 32 cycles.
- **The extra cycles come from the hardware.** When a Secure context is interrupted by a
  Non-Secure exception, the core also saves the callee-saved registers and an integrity
  signature on the Secure stack, then clears the registers so the Non-Secure handler
  cannot read Secure values.
- **Design implication:** this bound holds because the Secure service never masks
  interrupts. A Secure critical section (interrupts disabled, or Non-Secure priorities
  demoted with `AIRCR.PRIS`) would add its full length to Non-Secure latency. For real-time
  use, Secure services should stay interruptible and keep any critical sections short.
- **The Non-Secure baseline doesn't change under load.** HMAC in Non-Secure gave the same
  21-cycle latency as the idle loop.

**M5 caveats**
- Only the entry latency is measured. The cost of returning to the interrupted Secure code
  (unstacking and the integrity-signature check) is not yet measured.
- The Secure service uses no floating-point registers. If Secure code used the FPU, the
  core would also have to save and clear floating-point state, which would raise the
  latency. Not measured.
- TIM2 runs at the highest priority, with `AIRCR.PRIS = 0` and a warm instruction cache.

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
Markdown summary with the derived overheads, the M4 step breakdown and the M5
interrupt latency. Runs before M4 are named `m3_*`, later ones `bench_*`. Use
`-FromCsv <file>` to regenerate a summary from a saved CSV without the board.

## Repository layout
- `Secure/` Secure-world firmware: partition setup, clocks, crypto service, NSC API (`Inc/secure_nsc.h`)
- `NonSecure/` Non-Secure application: functional checks, the M3/M4 benchmark and the M5 interrupt-latency test
- `Common/` HMAC-SHA256 and mbedTLS configuration, built into both images
- `third_party/` Git submodules: CMSIS device and core headers, mbedTLS
- `results/` Benchmark CSVs and summaries, raw UART logs, capture script
- `docs/` Milestone notes and write-ups

## Next steps
- **Hardware vs software crypto:** compare the STM32L5 HASH accelerator with software
  SHA-256, and what sharing that peripheral between the worlds costs.
- **Remaining hygiene costs:** `hmac_sha256` itself zeroizes 160 bytes of key material
  with the same byte-wise `memset` in both worlds. Also compare newlib-nano with full
  newlib, whose `memset`/`memcpy` work a word at a time.
- **Pointer checks:** see whether a specialised check for the single SAU layout used here
  can undercut the generic 96-cycle `cmse_check_address_range` path without weakening it.
- **Code-placement sensitivity:** isolate the cause of the 639 to 404 cycle shift.
- **Interrupt return path and FPU context:** measure the cost of resuming interrupted
  Secure code, and the latency when Secure code has live floating-point state.
- **Cold-cache, first-call latency.**

## Author
Eugene Olowofela, P.Eng
