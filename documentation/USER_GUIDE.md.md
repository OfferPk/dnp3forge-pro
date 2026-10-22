# DNP3Forge Pro — Operations & User Guide

## 1\. Quick Start Guide

DNP3Forge Pro provides two complementary operational modes:

1. **Interactive Substation Web Studio**: Client-side single-page application (`source-code/index.html`) running entirely within any modern browser for interactive protocol dissection, CROB packing, and IIN diagnostics.  
2. **DevSecOps Python CLI Tool**: Headless command-line utility (`build/dnp3forge-cli.py`) for automated CI/CD pipeline gating, PCAP generation, and terminal security compliance audits.

---

## 2\. Interactive Web Studio Operations

### 2.1 Launching the Studio

Open `source-code/index.html` in Chrome, Firefox, Edge, or Safari. All calculations and packet dissections run client-side with zero external network connectivity required.

### 2.2 Navigation Tabs

- **FT3 Wireframe Studio**: Select application function codes (Select, Operate, Direct Operate, Read, Cold Restart), destination/source link addresses, and sequence numbers. Inspect the raw wire hex with automatically computed block CRCs and download binary `.pcap` files.  
- **CROB Relay Control Packer**: Configure Breaker Action (Trip, Close, NUL), Operation Type (Pulse On, Pulse Off, Latch On, Latch Off), count, and pulse on/off times. Observe the resulting 11-byte encoded structure.  
- **16-Bit IIN Diagnoser**: Enter 16-bit hex values (e.g., `0x0080`, `0x0010`, `0x0100`) to instantly diagnose internal indication flags and evaluate root-cause severity.  
- **NERC CIP Zero-Trust Auditor**: Test substation configurations against 10 critical security controls, apply industry presets (500kV Transmission, Distribution Feeder, Vulnerable Legacy), and evaluate compliance scores (0–100%).  
- **Code & Rule Synthesizer**: Generate production Outstation code for Python 3 (`opendnp3`), Embedded C++, and Suricata DNP3 DPI / Linux nftables industrial firewall rules.

---

## 3\. DevSecOps CLI Tool (`dnp3forge-cli.py`)

The CLI tool requires Python 3.8+ with standard library modules only (no pip dependencies).

### 3.1 Forging Frames & Exporting PCAP

\# Forge a Select-Before-Operate (SBO) Trip Frame and print wire hex

python3 build/dnp3forge-cli.py forge \--func select \--dest 1 \--src 2

\# Forge packet and export directly to a binary PCAP file

python3 build/dnp3forge-cli.py forge \--func operate \--output-pcap sbo-operate.pcap

### 3.2 Calculating CRC-16/DNP

\# Calculate CRC-16/DNP for an 8-byte FT3 header

python3 build/dnp3forge-cli.py calc-crc \--hex "05 64 05 c4 01 00 02 00"

\# Output:

\# Input (8 bytes): 05 64 05 c4 01 00 02 00

\# CRC-16/DNP: 0x6F6C (LE: 6c 6f)

### 3.3 Encoding CROB Relay Structures

\# Encode a 100ms Trip pulse command

python3 build/dnp3forge-cli.py crob-encode \--action trip \--op-type pulse-on \--on-time 100 \--off-time 100

### 3.4 Diagnosing Internal Indications (IIN)

\# Diagnose IIN Word 0x0080 (Device Restart)

python3 build/dnp3forge-cli.py iin-diagnose \--word 0x0080

\# Output:

\# IIN Word: 0x0080 (IIN1: 0x80, IIN2: 0x00)

\# Active Flags: 1

\#  \- \[WARN    \] IIN1.7  : Device Restart       | RTU restarted; cold restart occurred

### 3.5 Automated NERC CIP Compliance Auditing

\# Run audit against 500kV Transmission Substation preset

python3 build/dnp3forge-cli.py audit \--preset transmission

\# Run audit against Vulnerable Legacy preset with strict CI/CD gating (exits with code 1\)

python3 build/dnp3forge-cli.py audit \--preset vulnerable \--strict-ci

---

## 4\. CI/CD Pipeline Integration (GitHub Actions / GitLab CI)

Add DNP3 security auditing to your automated build workflows:

name: Substation NERC CIP Security Gate

on: \[push, pull\_request\]

jobs:

  dnp3-audit:

    runs-on: ubuntu-latest

    steps:

      \- uses: actions/checkout@v3

      \- name: Set up Python

        uses: actions/setup-python@v4

        with:

          python-version: '3.10'

      \- name: Run Zero-Trust DNP3 Security Audit

        run: |

          python3 build/dnp3forge-cli.py audit \--config config/substation-rtu.json \--strict-ci

If the calculated security score is below 80/100, the pipeline will immediately halt, preventing insecure SCADA configurations from reaching electrical substation control systems.