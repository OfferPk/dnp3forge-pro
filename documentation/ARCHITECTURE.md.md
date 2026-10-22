# DNP3Forge Pro — Technical Architecture & Specification

## 1\. Executive Summary

**DNP3Forge Pro (v1.0.0)** is an electrical substation SCADA protocol engineering studio, binary frame synthesizer, Control Relay Output Block (CROB) packer, 16-bit Internal Indications (IIN) diagnoser, and **NERC CIP / IEEE Std 1815-2012 Zero-Trust Security Auditor**. It provides mission-critical tooling for electric power transmission grids, distribution feeders, generation facilities, and municipal water utilities across North America, the UK, Europe, the UAE, and global smart grid deployments.

---

## 2\. IEEE Std 1815-2012 Protocol Architecture

DNP3 is structured across a three-layer Enhanced Performance Architecture (EPA) model with an added pseudo-transport layer:

\+-------------------------------------------------------------------------+

| Application Layer (APDU)                                                |

| Function Codes: Select (0x03), Operate (0x04), Read (0x01), IIN Flags   |

\+-------------------------------------------------------------------------+

| Object Layer (Objects & Variations)                                     |

| CROB (Group 12 Var 1), Binary Inputs (G1), Analog Inputs (G30), Class 0-3|

\+-------------------------------------------------------------------------+

| Transport Layer (Pseudo-Transport Layer)                                |

| 1-Byte Header: \[FIN:1\] \[FIR:1\] \[SEQ: 0..63\] Multi-Frame Assembly        |

\+-------------------------------------------------------------------------+

| Data Link Layer (FT3 Frame)                                             |

| 10-Byte Header (Sync 0x0564, Length, Control, Dest, Src, CRC) \+ Blocks  |

\+-------------------------------------------------------------------------+

| Physical / Network Transport Layer                                      |

| TCP/UDP Port 20000 (RFC 793 / RFC 768\) or RS-485 Serial Lines          |

\+-------------------------------------------------------------------------+

### 2.1 FT3 Data Link Layer (10-Octet Header \+ 16-Octet Chunk CRCs)

The FT3 frame specification mandates strict synchronization, address routing, and block error detection:

1. **Sync Octets (2 Octets)**: Always `0x05, 0x64`.  
2. **Length (1 Octet)**: Number of user octets \+ 5 (Control byte \+ 2 destination bytes \+ 2 source bytes). Maximum length is 255\.  
3. **Control (1 Octet)**:  
   - Bit 7: `DIR` (1 \= Master to Outstation, 0 \= Outstation to Master)  
   - Bit 6: `PRM` (1 \= Primary frame, 0 \= Secondary response)  
   - Bit 5: `FCB` (Frame Count Bit, toggles on successful confirmed frames)  
   - Bit 4: `FCV` (Frame Count Valid)  
   - Bits 0-3: Link Function Code (`0x04` \= Unconfirmed User Data, `0x03` \= Confirmed User Data, `0x00` \= Reset Link)  
4. **Destination Address (2 Octets, Little-Endian)**: 0 to 65519 unicast, `0xFFFF` All-Stations broadcast.  
5. **Source Address (2 Octets, Little-Endian)**: Address of sending host.  
6. **Header CRC (2 Octets, Little-Endian)**: Inverted CRC-16/DNP across the first 8 bytes.  
7. **User Data Chunks**: Sliced into segments of up to 16 octets, each followed by a mandatory 2-octet CRC-16/DNP.

### 2.2 CRC-16/DNP Calculation Algorithm

- **Polynomial**: `0x3D65` (represented in bit-reversed order as `0xA6BC`).  
- **Initial Register Value**: `0x0000`.  
- **Final Inversion**: `~CRC & 0xFFFF` (XOR with `0xFFFF`).  
- **Endianness on Wire**: Little-Endian (low octet first, high octet second).

---

## 3\. Control Relay Output Block (CROB — Group 12 Var 1\)

High-voltage circuit breakers (vacuum, SF6, oil) and transformer tap changers are actuated via CROB structures:

\+--------------------+--------------+-------------------+--------------------+--------------+

| Control Code (1B)  | Count (1B)   | On-Time (4B, LE)  | Off-Time (4B, LE)  | Status (1B)  |

\+--------------------+--------------+-------------------+--------------------+--------------+

- **Control Code (1 Octet)**:  
  - Bits 6-7: Action (`0` \= NUL, `1` \= Close Breaker, `2` \= Trip Breaker).  
  - Bit 5: Clear Flag.  
  - Bit 4: Queue Flag.  
  - Bits 0-3: Operation Type (`1` \= Pulse On, `2` \= Pulse Off, `3` \= Latch On, `4` \= Latch Off).  
- **Select-Before-Operate (SBO)**: Breakers mandate a two-step handshake:  
  1. Master sends `Function 0x03 (Select)` with CROB parameters. Outstation verifies arming parameters and arms relay for 5-10 seconds.  
  2. Master sends `Function 0x04 (Operate)` with identical CROB parameters. Outstation fires physical relay contact.

---

## 4\. 16-Bit Internal Indications (IIN) Diagnostics

Every DNP3 Response (`Function 0x81`) contains a 16-bit IIN bitfield immediately following the function code:

- **IIN 1 (First Octet)**:  
  - Bit 0: *All Stations* — Broadcast received.  
  - Bit 1: *Class 1 Events* — High-priority event data pending poll.  
  - Bit 2: *Class 2 Events* — Medium-priority event data pending poll.  
  - Bit 3: *Class 3 Events* — Low-priority event data pending poll.  
  - Bit 4: *Need Time* — Outstation clock desynchronized.  
  - Bit 5: *Local Control* — Certain physical points locked in local manual mode.  
  - Bit 6: *Device Trouble* — Critical hardware, power supply, or analog sensor fault.  
  - Bit 7: *Device Restart* — Outstation underwent power reset or cold reboot.  
- **IIN 2 (Second Octet)**:  
  - Bit 0: *Bad Function Code* — Function code unsupported.  
  - Bit 1: *Object Unknown* — Requested Group/Variation unmapped.  
  - Bit 2: *Parameter Error* — Invalid qualifier or out-of-range index.  
  - Bit 3: *Event Buffer Overflow* — Event queue saturated; historical points lost.  
  - Bit 4: *Already Executing* — SBO or command collision.  
  - Bit 5: *Configuration Corrupt* — Outstation EEPROM/Flash corrupted.

---

## 5\. 10-Point NERC CIP Zero-Trust Substation Security Rubric

1. **IEEE 1815-2012 SAv5 Secure Authentication (10 pts)**: Require HMAC-SHA-256 or AES-GMAC challenge-response. (10 pts)  
2. **Transport Layer Encryption (10 pts)**: Prohibit plaintext TCP 20000; mandate IPsec ESP or TLS 1.3 encapsulation. (10 pts)  
3. **Select-Before-Operate (SBO) Relay Enforcement (10 pts)**: Prohibit Direct Operate on high-voltage circuit breakers. (10 pts)  
4. **Unsolicited Response Storm Backoff (10 pts)**: Mandate backoff delay (\>= 500ms) to prevent thundering herd crashes during SCADA restarts. (10 pts)  
5. **CROB Role-Based Access Control (10 pts)**: Restrict relay actuation to authenticated dispatch operator accounts. (10 pts)  
6. **Link Address Destination/Source Whitelisting (10 pts)**: Strictly validate authorized link address pairs. (10 pts)  
7. **Broadcast Address (0xFFFF) Write/Operate Block (10 pts)**: Block all control commands sent to broadcast. (10 pts)  
8. **Anti-Replay Challenge Sequence & Key Rotation (10 pts)**: Enforce replay sequence tracking with \<= 15-minute key rotation. (10 pts)  
9. **Remote Cold/Warm Restart Hardening (10 pts)**: Restrict or disable function codes `0x0E` and `0x0F`. (10 pts)  
10. **Substation VLAN Isolation & Suricata DNP3 DPI (10 pts)**: Enforce bay-level network segmentation with DPI inspecting TCP 20000\. (10 pts) Total: 100 points. Pass threshold: \>= 80 points.