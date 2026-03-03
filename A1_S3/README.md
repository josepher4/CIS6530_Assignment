# CIS6530 A1_S3 - PE Opcode Extraction Pipeline

**Authors**: MJ 
**Date**: March 03 2026  
**Environment**: REMnux Noble AMD64 (VMware Workstation)

Automated opcode extraction from 48 malware samples (`.exe`/`.dll`).

## Features
- **Pure Python** implementation (pefile + capstone)
- **Multi-section extraction** (`.text`, `.rdata`, EXECUTE flagged sections)
- **Packed/obfuscated malware** resilient (entry point fallback)
- **Progress bar** (tqdm) + **JSON logging** + **statistics**
