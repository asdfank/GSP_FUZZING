## Project focus

This repository is a research-oriented fuzzing project based on kAFL, with a focus on:

- multi-snapshot fuzzing under VFIO device passthrough,
- GPU driver fuzzing,
- hardware-in-the-loop execution models,
- reproducibility and coverage collection in non-deterministic environments.

The project is currently in an experimental stage and is maintained by a single developer.
## Fuzzing with Hardware-in-the-Loop

This project explores fuzzing targets that interact with real hardware during execution. In this model, the device becomes part of the fuzzing loop, which directly affects both coverage collection and snapshot reliability.

### Core decision: is reset reliable?

A hardware-in-the-loop fuzzing setup depends heavily on whether the device can be reset into a known-good state between test cases.

A reset is considered reliable when:

- the device and driver return to a known-good state,
- the same test case produces the same observable behavior and coverage,
- the device consistently accepts new work without timeout storms or persistent error states.

For large stateful devices such as GPUs, this assumption is often hard to satisfy. Significant internal micro-architectural state may survive an ordinary device reset. In practice, some setups may require a full platform reboot to recover a truly clean baseline.

### If reset is reliable: snapshots are possible

If the device can be restored to a known-good state between inputs, snapshot-based fuzzing remains possible. Two snapshot placements are especially relevant:

#### 1. Pre-init snapshot

In this model, the snapshot is taken before driver initialization.

- Restore to a pre-driver state
- Re-run device enumeration and driver initialization on every iteration
- Execute the harness and test case
- Return to the snapshot

This approach is slower, but often more robust for complex devices because it avoids carrying partially-initialized driver or device state across iterations.

#### 2. Post-init snapshot

In this model, the snapshot is taken after driver initialization has completed.

- Restore to a post-init guest state
- Reset the device
- Re-establish configured state
- Execute the harness and test case
- Return to the snapshot for the next input

This approach keeps expensive vendor driver initialization out of the hot loop, improving iteration speed. However, it only works if device and driver state can be reset and re-armed in a cheaper and deterministic way.

### If reset is unreliable: disable snapshots

If reliable reset is not possible, fuzzing can still proceed by disabling snapshot mode entirely. This is closer to a syzkaller-style campaign:

- no reset between inputs,
- high throughput,
- unavoidable state drift,
- reduced determinism.

This mode may still be useful, but it introduces additional challenges for both coverage and triage.

### Coverage collection considerations

Without snapshotting, guest memory state drifts over time. Intel PT depends on a relatively stable guest memory layout and page-cache-based decoding assumptions. In a drifting, non-snapshot system, PT decoding may stall or miss execution, making coverage much less reliable.

When possible, software instrumentation such as KCOV should be treated as the authoritative coverage source, while PT should be considered best-effort only.

### Non-determinism and feedback noise

With real hardware in the loop, the system must be treated as non-deterministic.

A major failure mode is that the device or driver enters a broken state and starts returning errors for all subsequent inputs. When that happens:

- coverage may stop changing,
- inputs may appear uninteresting and get discarded,
- the original crashing or hanging input may fail replay validation because execution now follows a different path.

This makes triage and reproducibility substantially harder than in ordinary snapshot-driven fuzzing.

### DMA caveat

DMA is asynchronous. A test case may submit DMA work that completes later, meaning memory writes from one iteration can land during the next iteration and contaminate feedback.

Before accepting the next input, the system should ensure that all outstanding DMA activity has quiesced, or that reset and re-arming are strong enough to prevent DMA completion from leaking across iterations.

### Why this matters for this repository

The long-term goal of this project is to understand how kAFL-style fuzzing workflows can be adapted for VFIO passthrough and GPU-driver-related targets, where reset reliability, snapshot placement, coverage collection, and reproducibility become central engineering and security challenges.
