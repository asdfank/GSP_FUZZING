# GSP_FUZZING

**GSP_FUZZING** is an experimental open-source fuzzing project based on **kAFL**, focused on enabling **multi-snapshot fuzzing under VFIO device passthrough** and exploring **GPU driver fuzzing**.

## Overview

This project targets a difficult and underexplored systems-security problem: how to make fuzzing practical and repeatable when the target depends on **VFIO passthrough** and hardware-backed execution paths.

The long-term aim is to investigate whether fuzzing infrastructure can better support:

- passthrough-backed targets
- richer snapshot and restore workflows
- GPU driver attack surfaces
- more reproducible experiments for low-level security research

## Motivation

Snapshot-based fuzzing works well for many VM-based targets, but device passthrough introduces new challenges:

- restoring clean execution state is harder
- device state may not reset like ordinary guest memory
- reproducibility becomes more fragile
- driver-facing attack surfaces are complex and stateful

This repository exists to explore these problems in a practical way.

## Project goals

- Study **multi-snapshot fuzzing** designs for **VFIO passthrough**
- Extend or adapt **kAFL-style workflows** to hardware-assisted targets
- Explore **GPU driver fuzzing** as a real-world use case
- Build a reusable foundation for future systems-security experiments

## Repository layout

Current top-level directories include:

- `kAFL/`
- `gvisor/`

The codebase currently spans multiple languages, including **C, Go, C++, and Python**, consistent with low-level fuzzing, systems tooling, and infrastructure work.

## Status

This is an **early-stage**, **solo-maintained**, and **research-oriented** project.

The project is still evolving, and documentation, workflow details, and implementation structure will continue to change as experiments progress.

## Intended audience

This repository is mainly intended for:

- security researchers
- fuzzing practitioners
- kernel / driver researchers
- virtualization and passthrough security developers
- people studying advanced VM-based fuzzing workflows

## Roadmap

Planned improvements include:

- clearer architecture documentation
- setup instructions
- experiment notes and limitations
- GPU-driver-focused case studies
- crash triage and result analysis tooling
- better reproducibility for fuzzing experiments

## Acknowledgments

This work is inspired by and builds on the ideas behind **kAFL** and related fuzzing research.

## License

See the repository and upstream component license files for details.
