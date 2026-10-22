# DNP3Forge Pro (v1.0.0)

> **IEEE Std 1815-2012 DNP3 Substation Protocol Studio, FT3 Frame & CRC-16/DNP Calculator, CROB Relay Control & SBO Sequence Visualizer, 16-Bit IIN Diagnoser & NERC CIP Substation Security Auditor.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](http://LICENSE) [![Standards: IEEE Std 1815-2012 / NERC CIP](https://img.shields.io/badge/Standards-IEEE%201815--2012%20%7C%20NERC%20CIP-f59e0b.svg)](https://standards.ieee.org) ![Build Status: Passing](https://img.shields.io/badge/Build-Passing%20\(10%2F10%20Tests\)-10b981.svg) ![Platform: Web + Python 3 CLI](https://img.shields.io/badge/Platform-Web%20%7C%20Python%203%20CLI-8b5cf6.svg)

---

## 1\. Overview & Problem Statement

Throughout the electric power transmission and distribution grids of North America, the United Kingdom, Europe, the UAE, and global utilities, **IEEE Std 1815-2012 (DNP3)** serves as the primary operational telemetry and control protocol. Connecting high-voltage electrical substations, protective relays, remote terminal units (RTUs), and energy management systems (EMS/SCADA) across TCP/UDP port 20000 or serial RS-485 links, DNP3 directs real-time breaker tripping, voltage regulation, and feeder automation.

However, operating and securing DNP3 networks introduces severe technical complexity and physical risk:

1. **Mandatory 16-Byte Chunk CRC-16/DNP Inversion**: The FT3 framing specification divides user data into blocks of up to 16 octets, each protected by an inverted CRC-16 polynomial (`0x3D65` bit-reversed `0xA6BC`). Any single miscalculated CRC octet causes the receiving IED to silently discard the entire packet.  
2. **Breaker Actuation Hazards (Select-Before-Operate vs Direct Operate)**: Firing control relay commands (CROB Group 12 Var 1\) without a two-step Select-Before-Operate (SBO) sequence can inadvertently disconnect 500kV circuit breakers or trip transmission lines.  
3. **Cryptic 16-Bit Internal Indications (IIN)**: Responses contain a 2-byte bitfield indicating internal conditions (e.g. Device Restart, Need Time, Event Buffer Overflow, Device Trouble). Interpreting these bitwise flags during fault emergencies requires rapid diagnostic tools.  
4. **Unencrypted Legacy TCP Port 20000 Exposure**: Legacy outstations frequently run over cleartext TCP without IEEE 1815 SAv5 Secure Authentication, leaving substations vulnerable to rogue replay attacks and command injection (such as Industroyer / CrashOverride).  
5. **Lack of Automated CI/CD Compliance Gating**: Utility IT/OT pipelines lack lightweight, standalone tools to verify RTU configurations against NERC CIP requirements prior to deployment.

**DNP3Forge Pro** solves these challenges with an interactive Substation Web Studio and a zero-dependency Python 3 DevSecOps CLI tool.

---

## 2\. Core Capabilities

- **FT3 Wireframe Studio**: Live bitwise generation and deep dissection of DNP3 FT3 frames (10-byte header, sync `0x0564`, length calculation, control octet, destination/source address, and block CRCs).  
- **CRC-16/DNP Calculator**: Real-time bit-reversed inverted polynomial calculation over arbitrary octet buffers.  
- **CROB Relay Control Packer**: Visual encoder for Control Relay Output Blocks (Group 12 Var 1\) supporting Trip/Close breaker actions, Pulse On/Off, Latch On/Off, and on/off millisecond pulse timing.  
- **16-Bit IIN Diagnoser**: Instant root-cause decoding of 14 standard Internal Indications flags across IIN1 and IIN2 with severity classification.  
- **NERC CIP Zero-Trust Auditor**: 10-point compliance evaluator scoring substation configurations (0–100%, Grades A+ to F) with automated CI/CD gating (`exit 1` on score \< 80).  
- **Network Wire Assembler & PCAP Generator**: Generates full IEEE 802.3 Ethernet II \+ IPv4 \+ TCP (port 20000\) \+ DNP3 frames with RFC 1071 IP/TCP checksums and CRC32 FCS, exportable directly as standard `.pcap` files for Wireshark.  
- **Multi-Platform Synthesizer**: 1-click generation of production Outstation code for Python 3 (`opendnp3`), Embedded C++, and Suricata DNP3 DPI / Linux `nftables` substation perimeter firewall rules.

---

## 3\. Directory Structure

product\_138/

├── source-code/

│   ├── index.html                   \# Substation Web Studio Interface

│   ├── dnp3-forge.css               \# Glassmorphism Dark Theme Styles

│   ├── dnp3-protocol-engine.js      \# FT3 Framing, CRC-16/DNP & PCAP Engine

│   ├── dnp3-security-auditor.js     \# 10-Point NERC CIP / SAv5 Auditor

│   ├── dnp3-config-synthesizer.js   \# Python, C++, Suricata DPI & Firewall Rules

│   └── app.js                       \# Studio State & UI Event Controller

├── build/

│   ├── dnp3forge-cli.py             \# Zero-Dependency Python 3 DevSecOps CLI

│   └── dnp3forge-pro-v1.0.0.zip     \# Complete Distributable Release Archive

├── documentation/

│   ├── ARCHITECTURE.md              \# Technical Protocol & Framing Spec

│   ├── USER\_GUIDE.md                \# Operations, CLI Manual & CI/CD Guide

│   └── MONETIZATION\_AND\_MARKETING\_PLAYBOOK.md \# Target Personas & GTM Strategy

├── screenshots/

│   ├── dnp3-studio-preview.svg      \# Visual Studio Interface Preview

│   └── dnp3-architecture-diagram.svg\# Substation Architecture & Protocol Diagram

└── README.md                        \# Master Documentation

---

## 4\. Quick Start & CLI Usage

### Running the Web Studio

Open `source-code/index.html` in any modern web browser. No server setup or external dependencies are required.

### Using the Python CLI Tool

\# Calculate CRC-16/DNP for an 8-byte FT3 header

python3 build/dnp3forge-cli.py calc-crc \--hex "05 64 05 c4 01 00 02 00"

\# Forge a Select-Before-Operate (SBO) Trip Frame and print wire hex

python3 build/dnp3forge-cli.py forge \--func select \--dest 1 \--src 2

\# Encode a 100ms Trip pulse CROB structure

python3 build/dnp3forge-cli.py crob-encode \--action trip \--op-type pulse-on \--on-time 100

\# Diagnose an IIN word (0x0080 \= Device Restart)

python3 build/dnp3forge-cli.py iin-diagnose \--word 0x0080

\# Run a NERC CIP Zero-Trust Security Audit with strict CI/CD gating

python3 build/dnp3forge-cli.py audit \--preset transmission \--strict-ci

\# Export a 2-packet SBO Trip PCAP capture for Wireshark analysis

python3 build/dnp3forge-cli.py export-pcap \--output sbo-trip.pcap

---

## 5\. Automated Verification & Testing

DNP3Forge Pro includes an automated 10-test verification suite (`test_dnp3forge.py`):

1. **CRC-16/DNP Calculation**: Validates exact polynomial inversion across test vectors (`0x05 0x64 0x05 0xC4 0x01 0x00 0x02 0x00` \-\> `0x6F6C`).  
2. **FT3 Data Link Layer Framing**: Verifies 10-byte header, sync bytes, length calculation, and address packing.  
3. **Transport & APDU Assembly**: Verifies single-byte transport sequence and application function code serialization.  
4. **CROB Relay Control Block Packing**: Validates 11-byte structure, Trip/Close action codes, and timing parameters.  
5. **16-Bit IIN Diagnoser Accuracy**: Validates bitwise extraction across all 14 indication flags.  
6. **Ethernet/IP/TCP (Port 20000\) Assembly**: Verifies calculated RFC 1071 IP/TCP checksums and CRC32 FCS.  
7. **Binary PCAP Generation**: Validates Libpcap 2.4 header layout and multi-packet capture packaging.  
8. **Cross-Runtime Binary Parity**: Confirms byte-for-byte exact frame assembly between Python 3 and Node.js engines.  
9. **Transmission Substation Preset Audit**: Confirms 100/100 Grade A+ evaluation.  
10. **Vulnerable Legacy Preset Audit**: Confirms 0/100 Grade F evaluation and strict CI/CD exit code 1 halting.

---

## 6\. Commercial Model & Pricing

- **Community Edition (Free)**: Web Studio UI, basic frame synthesis, CROB relay packer, core IIN decoder.  
- **Professional Seat (\$49/month or \$490/year)**: Python DevSecOps CLI (`dnp3forge-cli.py`), batch PCAP export, Suricata DNP3 DPI and Linux nftables firewall rule generator.  
- **Enterprise Site License (\$2,400/year)**: Unlimited engineering seats per operating utility, automated CI/CD security gating runner, priority SLA support.

---

## 7\. Operational Scope & Known Limitations

DNP3Forge Pro executes client-side simulation, packet serialization, dissection, and static rule synthesis. Direct serial RS-485 transceiver bus arbitration, millisecond hardware relay contact debounce, and million-point high-frequency SCADA historian polling require physical industrial RTUs or dedicated production DNP3 stacks (`OpenDNP3`).