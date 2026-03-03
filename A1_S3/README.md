# CIS6530 A1_S3 - PE Opcode Extraction Pipeline

**Author**: MJ 
**Contributors**: KH

**Date**: March 03 2026  
**Environment**: REMnux Noble AMD64 (VMware Workstation)

Automated opcode extraction from 48 malware samples (`.exe`/`.dll`). Extracts executable instructions (mov/push/call/jmp) from all EXECUTE sections of Windows PE files using pefile (file dissection) + capstone (code translation).

## Features
- **Pure Python** implementation (pefile + capstone)
- **Multi-section extraction** (`.text`, `.rdata`, EXECUTE flagged sections)
- **Packed/obfuscated malware** resilient (entry point fallback)
- **Progress bar** (tqdm) + **JSON logging** + **statistics**

## Safety
- VM snapshot recommended
- Host-only networking
