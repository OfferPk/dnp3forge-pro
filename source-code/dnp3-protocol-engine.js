/**
 * DNP3Forge Pro - IEEE Std 1815-2012 DNP3 Substation Protocol Engine (v1.0.0)
 * Handles FT3 10-Byte Link Framing, CRC-16/DNP Inverted Block Checksums,
 * Transport Layer, APDU Function Codes, CROB Relay Control, and PCAP Generation.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.DNP3ProtocolEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // --- Constants & Enums ---
  const LINK_FUNCTION_CODES = {
    // Primary to Secondary
    RESET_LINK: 0,
    RESET_USER_PROCESS: 1,
    TEST_LINK: 2,
    CONFIRMED_USER_DATA: 3,
    UNCONFIRMED_USER_DATA: 4,
    REQUEST_LINK_STATUS: 9,
    // Secondary to Primary
    ACK: 0,
    NACK: 1,
    LINK_STATUS: 11
  };

  const APP_FUNCTION_CODES = {
    CONFIRM: 0x00,
    READ: 0x01,
    WRITE: 0x02,
    SELECT: 0x03,
    OPERATE: 0x04,
    DIRECT_OPERATE: 0x05,
    DIRECT_OPERATE_NO_ACK: 0x06,
    COLD_RESTART: 0x0E,
    WARM_RESTART: 0x0F,
    ENABLE_UNSOLICITED: 0x14,
    DISABLE_UNSOLICITED: 0x15,
    RESPONSE: 0x81,
    UNSOLICITED_RESPONSE: 0x82
  };

  const CROB_OP_TYPES = {
    NUL: 0,
    PULSE_ON: 1,
    PULSE_OFF: 2,
    LATCH_ON: 3,
    LATCH_OFF: 4
  };

  const CROB_ACTION = {
    NUL: 0,
    CLOSE: 1,
    TRIP: 2
  };

  const IIN_BITS = {
    // IIN 1 (First Octet)
    ALL_STATIONS: { octet: 0, bit: 0, name: 'All Stations', desc: 'Broadcast message received.' },
    CLASS_1_EVENTS: { octet: 0, bit: 1, name: 'Class 1 Events', desc: 'Class 1 data available for polling.' },
    CLASS_2_EVENTS: { octet: 0, bit: 2, name: 'Class 2 Events', desc: 'Class 2 data available for polling.' },
    CLASS_3_EVENTS: { octet: 0, bit: 3, name: 'Class 3 Events', desc: 'Class 3 data available for polling.' },
    NEED_TIME: { octet: 0, bit: 4, name: 'Need Time', desc: 'Outstation internal clock requires synchronization.' },
    LOCAL_CONTROL: { octet: 0, bit: 5, name: 'Local Control', desc: 'Some points in local control mode.' },
    DEVICE_TROUBLE: { octet: 0, bit: 6, name: 'Device Trouble', desc: 'Hardware or sensor diagnostic problem detected.' },
    DEVICE_RESTART: { octet: 0, bit: 7, name: 'Device Restart', desc: 'Outstation has restarted since last cleared.' },
    // IIN 2 (Second Octet)
    BAD_FUNCTION_CODE: { octet: 1, bit: 0, name: 'Bad Function Code', desc: 'Requested function code not supported.' },
    OBJECT_UNKNOWN: { octet: 1, bit: 1, name: 'Object Unknown', desc: 'Requested object group/variation unknown.' },
    PARAMETER_ERROR: { octet: 1, bit: 2, name: 'Parameter Error', desc: 'Invalid range, qualifier, or parameter.' },
    EVENT_BUFFER_OVERFLOW: { octet: 1, bit: 3, name: 'Event Buffer Overflow', desc: 'Event buffer overflowed; events lost.' },
    ALREADY_EXECUTING: { octet: 1, bit: 4, name: 'Already Executing', desc: 'Requested operation is already in progress.' },
    CONFIG_CORRUPT: { octet: 1, bit: 5, name: 'Configuration Corrupt', desc: 'Outstation configuration memory corrupted.' }
  };

  // --- CRC-16/DNP Calculator (IEEE Std 1815-2012) ---
  // Polynomial: 0x3D65, bit-reversed: 0xA6BC, initial: 0x0000, final XOR: 0xFFFF
  function crc16Dnp(data) {
    let crc = 0x0000;
    const len = data.length;
    for (let i = 0; i < len; i++) {
      crc ^= data[i];
      for (let j = 0; j < 8; j++) {
        if (crc & 1) {
          crc = (crc >>> 1) ^ 0xA6BC;
        } else {
          crc >>>= 1;
        }
      }
    }
    return ((~crc) & 0xFFFF) >>> 0;
  }

  // IEEE 802.3 Ethernet FCS (CRC32)
  function crc32(buffer) {
    const table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[i] = c >>> 0;
    }
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < buffer.length; i++) {
      crc = table[(crc ^ buffer[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  // RFC 1071 IP Checksum
  function ipChecksum(headerBytes) {
    let sum = 0;
    for (let i = 0; i < headerBytes.length; i += 2) {
      if (i === 10) continue;
      const word = (headerBytes[i] << 8) + (headerBytes[i + 1] || 0);
      sum += word;
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }

  // RFC 793 TCP Checksum
  function tcpChecksum(srcIp, dstIp, tcpBytes) {
    let sum = 0;
    const srcParts = srcIp.split('.').map(Number);
    const dstParts = dstIp.split('.').map(Number);
    sum += (srcParts[0] << 8) + srcParts[1];
    sum += (srcParts[2] << 8) + srcParts[3];
    sum += (dstParts[0] << 8) + dstParts[1];
    sum += (dstParts[2] << 8) + dstParts[3];
    sum += 6; // Protocol TCP
    sum += tcpBytes.length;

    for (let i = 0; i < tcpBytes.length; i += 2) {
      if (i === 16) continue;
      const word = (tcpBytes[i] << 8) + (tcpBytes[i + 1] !== undefined ? tcpBytes[i + 1] : 0);
      sum += word;
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (~sum) & 0xFFFF;
  }

  function bytesToHex(bytes, delimiter = ' ') {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(delimiter);
  }

  function hexToBytes(hexStr) {
    const clean = hexStr.replace(/[^0-9a-fA-F]/g, '');
    const bytes = [];
    for (let i = 0; i < clean.length; i += 2) {
      bytes.push(parseInt(clean.substr(i, 2), 16));
    }
    return bytes;
  }

  // --- FT3 Data Link Layer Framing ---
  function buildFt3Frame(userData, options = {}) {
    const dest = options.dest !== undefined ? options.dest : 1;
    const src = options.src !== undefined ? options.src : 2;
    // Default control: DIR=1, PRM=1, FCB=0, FCV=0, Function=4 (Unconfirmed User Data) -> 0xC4
    const control = options.control !== undefined ? options.control : 0xC4;

    const length = userData.length + 5; // User bytes + control(1) + dest(2) + src(2)
    const hdr = [
      0x05, 0x64,
      length & 0xFF,
      control & 0xFF,
      dest & 0xFF, (dest >> 8) & 0xFF,
      src & 0xFF, (src >> 8) & 0xFF
    ];
    const hdrCrc = crc16Dnp(hdr);
    hdr.push(hdrCrc & 0xFF, (hdrCrc >> 8) & 0xFF);

    // Chunk user data into blocks of up to 16 bytes, each followed by 2-byte CRC
    const frame = [...hdr];
    for (let i = 0; i < userData.length; i += 16) {
      const chunk = userData.slice(i, i + 16);
      const cCrc = crc16Dnp(chunk);
      frame.push(...chunk);
      frame.push(cCrc & 0xFF, (cCrc >> 8) & 0xFF);
    }

    return frame;
  }

  // --- CROB (Control Relay Output Block) Packer ---
  function encodeCrob(options = {}) {
    // OpType: 1=PulseOn, 2=PulseOff, 3=LatchOn, 4=LatchOff
    const opType = options.opType !== undefined ? options.opType : CROB_OP_TYPES.PULSE_ON;
    // Action: 0=NUL, 1=Close, 2=Trip
    const action = options.action !== undefined ? options.action : CROB_ACTION.TRIP;
    const count = options.count !== undefined ? options.count : 1;
    const onTime = options.onTime !== undefined ? options.onTime : 100; // ms
    const offTime = options.offTime !== undefined ? options.offTime : 100; // ms
    const status = options.status !== undefined ? options.status : 0; // 0 = Success

    const controlCode = ((action & 0x03) << 6) | (opType & 0x0F);

    const bytes = [
      controlCode & 0xFF,
      count & 0xFF,
      onTime & 0xFF, (onTime >> 8) & 0xFF, (onTime >> 16) & 0xFF, (onTime >> 24) & 0xFF,
      offTime & 0xFF, (offTime >> 8) & 0xFF, (offTime >> 16) & 0xFF, (offTime >> 24) & 0xFF,
      status & 0xFF
    ];
    return bytes;
  }

  // --- Application APDU Builder ---
  function buildApdu(options = {}) {
    const transportSeq = options.transportSeq !== undefined ? options.transportSeq : 0;
    const appSeq = options.appSeq !== undefined ? options.appSeq : 1;
    const funcCode = options.funcCode !== undefined ? options.funcCode : APP_FUNCTION_CODES.SELECT;

    // Transport Byte: FIR=1 (0x40), FIN=1 (0x80) -> 0xC0 | seq
    const th = 0xC0 | (transportSeq & 0x3F);

    // Application Control Byte: FIR=1 (0x80), FIN=1 (0x40), CON=0, UNS=0 -> 0xC0 | (seq & 0x0F)
    const ac = 0xC0 | (appSeq & 0x0F);

    const apdu = [th, ac, funcCode & 0xFF];

    // Response includes 2-byte IIN
    if (funcCode === APP_FUNCTION_CODES.RESPONSE || funcCode === APP_FUNCTION_CODES.UNSOLICITED_RESPONSE) {
      const iin1 = options.iin1 || 0x00;
      const iin2 = options.iin2 || 0x00;
      apdu.push(iin1 & 0xFF, iin2 & 0xFF);
    }

    // Objects payload
    if (options.objectsPayload && options.objectsPayload.length > 0) {
      apdu.push(...options.objectsPayload);
    }

    return apdu;
  }

  // --- Internal Indications (IIN) Diagnoser ---
  function diagnoseIin(iin1, iin2) {
    const flags = [];
    Object.keys(IIN_BITS).forEach(key => {
      const item = IIN_BITS[key];
      const octetVal = item.octet === 0 ? iin1 : iin2;
      const isSet = (octetVal & (1 << item.bit)) !== 0;
      if (isSet) {
        flags.push({
          key,
          name: item.name,
          octet: item.octet + 1,
          bit: item.bit,
          description: item.desc,
          severity: (key === 'DEVICE_TROUBLE' || key === 'CONFIG_CORRUPT' || key === 'EVENT_BUFFER_OVERFLOW') ? 'CRITICAL' : (key.startsWith('CLASS_') ? 'INFO' : 'WARN')
        });
      }
    });

    return {
      iinRaw: `0x${((iin2 << 8) | iin1).toString(16).padStart(4, '0').toUpperCase()}`,
      iin1: `0x${iin1.toString(16).padStart(2, '0').toUpperCase()}`,
      iin2: `0x${iin2.toString(16).padStart(2, '0').toUpperCase()}`,
      activeFlagsCount: flags.length,
      flags
    };
  }

  // --- Dissector ---
  function dissectFt3Frame(bytes) {
    if (bytes.length < 10) {
      return { error: 'Incomplete FT3 Header (minimum 10 bytes required)' };
    }
    if (bytes[0] !== 0x05 || bytes[1] !== 0x64) {
      return { error: `Invalid FT3 Sync Bytes: 0x${bytes[0].toString(16)} 0x${bytes[1].toString(16)} (expected 0x05 0x64)` };
    }

    const length = bytes[2];
    const control = bytes[3];
    const dest = bytes[4] | (bytes[5] << 8);
    const src = bytes[6] | (bytes[7] << 8);
    const hdrCrc = bytes[8] | (bytes[9] << 8);

    const calcHdrCrc = crc16Dnp(bytes.slice(0, 8));
    const hdrCrcValid = calcHdrCrc === hdrCrc;

    const dir = (control & 0x80) !== 0;
    const prm = (control & 0x40) !== 0;
    const fcb = (control & 0x20) !== 0;
    const fcv = (control & 0x10) !== 0;
    const funcCode = control & 0x0F;

    // Extract User Data & verify chunk CRCs
    const userData = [];
    let pos = 10;
    let blockIdx = 0;
    let blocksValid = true;

    while (pos < bytes.length) {
      const remaining = bytes.length - pos;
      if (remaining < 3) break; // Need at least 1 byte data + 2 bytes CRC
      const dataLen = Math.min(16, remaining - 2);
      const dataChunk = bytes.slice(pos, pos + dataLen);
      const chunkCrc = bytes[pos + dataLen] | (bytes[pos + dataLen + 1] << 8);
      const calcChunkCrc = crc16Dnp(dataChunk);
      if (calcChunkCrc !== chunkCrc) {
        blocksValid = false;
      }
      userData.push(...dataChunk);
      pos += dataLen + 2;
      blockIdx++;
    }

    const result = {
      sync: '0x0564',
      lengthField: length,
      userDataBytesExtracted: userData.length,
      control: {
        raw: `0x${control.toString(16).padStart(2, '0').toUpperCase()}`,
        dir: dir ? 'MasterToOutstation' : 'OutstationToMaster',
        prm: prm ? 'Primary' : 'Secondary',
        fcb,
        fcv,
        functionCode: funcCode
      },
      addresses: {
        destination: dest,
        source: src
      },
      headerCrc: {
        wire: `0x${hdrCrc.toString(16).padStart(4, '0').toUpperCase()}`,
        calculated: `0x${calcHdrCrc.toString(16).padStart(4, '0').toUpperCase()}`,
        valid: hdrCrcValid
      },
      blockCrcsValid: blocksValid,
      transportLayer: null,
      applicationLayer: null
    };

    // If user data exists, parse transport and APDU
    if (userData.length >= 2) {
      const th = userData[0];
      result.transportLayer = {
        fin: (th & 0x80) !== 0,
        fir: (th & 0x40) !== 0,
        seq: th & 0x3F
      };

      if (userData.length >= 3) {
        const ac = userData[1];
        const apduFunc = userData[2];
        result.applicationLayer = {
          fir: (ac & 0x80) !== 0,
          fin: (ac & 0x40) !== 0,
          con: (ac & 0x20) !== 0,
          uns: (ac & 0x10) !== 0,
          seq: ac & 0x0F,
          functionCode: `0x${apduFunc.toString(16).padStart(2, '0').toUpperCase()}`
        };
      }
    }

    return result;
  }

  // --- Network Frame Assembler (Ethernet II + IPv4 + TCP Port 20000 + DNP3) ---
  function assembleEthernetTcpFrame(dnp3Bytes, options = {}) {
    const srcMac = [0x00, 0x1B, 0x1B, 0x11, 0x22, 0x33]; // Substation Gateway
    const dstMac = [0x00, 0x0E, 0x8C, 0x44, 0x55, 0x66]; // Substation RTU/IED
    const ethType = [0x08, 0x00]; // IPv4

    const srcIp = options.srcIp || '10.100.1.50'; // Control Center Master SCADA
    const dstIp = options.dstIp || '10.100.1.100'; // Feeder Breaker RTU
    const srcPort = options.srcPort || 49152;
    const dstPort = options.dstPort || 20000; // Standard IEEE 1815 DNP3 TCP port

    const srcParts = srcIp.split('.').map(Number);
    const dstParts = dstIp.split('.').map(Number);

    const tcpPayloadLength = dnp3Bytes.length;
    const tcpHeaderLength = 20;
    const totalTcpLength = tcpHeaderLength + tcpPayloadLength;
    const totalIpLength = 20 + totalTcpLength;

    // IPv4 Header
    const ipHeader = [
      0x45, 0x00,
      (totalIpLength >> 8) & 0xFF, totalIpLength & 0xFF,
      0x18, 0x15, // Ident (1815)
      0x40, 0x00, // Don't Fragment
      0x40,       // TTL 64
      0x06,       // TCP
      0x00, 0x00, // Checksum placeholder
      srcParts[0], srcParts[1], srcParts[2], srcParts[3],
      dstParts[0], dstParts[1], dstParts[2], dstParts[3]
    ];
    const ipChk = ipChecksum(ipHeader);
    ipHeader[10] = (ipChk >> 8) & 0xFF;
    ipHeader[11] = ipChk & 0xFF;

    // TCP Header
    const seqNum = options.tcpSeq || 0x00018150;
    const ackNum = options.tcpAck || 0x00028150;
    const tcpFlags = 0x18; // PSH, ACK

    const tcpHeader = [
      (srcPort >> 8) & 0xFF, srcPort & 0xFF,
      (dstPort >> 8) & 0xFF, dstPort & 0xFF,
      (seqNum >> 24) & 0xFF, (seqNum >> 16) & 0xFF, (seqNum >> 8) & 0xFF, seqNum & 0xFF,
      (ackNum >> 24) & 0xFF, (ackNum >> 16) & 0xFF, (ackNum >> 8) & 0xFF, ackNum & 0xFF,
      (5 << 4), tcpFlags,
      0xFA, 0xF0, // Window size 64240
      0x00, 0x00, // Checksum placeholder
      0x00, 0x00
    ];

    const fullTcp = [...tcpHeader, ...dnp3Bytes];
    const tcpChk = tcpChecksum(srcIp, dstIp, fullTcp);
    fullTcp[16] = (tcpChk >> 8) & 0xFF;
    fullTcp[17] = tcpChk & 0xFF;

    let frame = [...srcMac, ...dstMac, ...ethType, ...ipHeader, ...fullTcp];
    while (frame.length < 60) {
      frame.push(0x00);
    }

    const fcs = crc32(frame);
    const fullFrameWithFcs = [
      ...frame,
      fcs & 0xFF, (fcs >> 8) & 0xFF, (fcs >> 16) & 0xFF, (fcs >> 24) & 0xFF
    ];

    return {
      frameBytes: frame,
      fullFrameWithFcs: fullFrameWithFcs,
      ipChecksum: ipChk,
      tcpChecksum: tcpChk,
      fcs: fcs,
      wireLength: fullFrameWithFcs.length
    };
  }

  // --- PCAP Generator ---
  function generatePcap(frames) {
    const globalHeader = [
      0xD4, 0xC3, 0xB2, 0xA1,
      0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xFF, 0xFF, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00
    ];

    const pcapBytes = [...globalHeader];
    const now = Math.floor(Date.now() / 1000);

    frames.forEach((frameObj, idx) => {
      const bytes = frameObj.frameBytes || frameObj;
      const len = bytes.length;
      const sec = now + idx;
      const usec = (idx * 50000) % 1000000;

      const packetHeader = [
        sec & 0xFF, (sec >> 8) & 0xFF, (sec >> 16) & 0xFF, (sec >> 24) & 0xFF,
        usec & 0xFF, (usec >> 8) & 0xFF, (usec >> 16) & 0xFF, (usec >> 24) & 0xFF,
        len & 0xFF, (len >> 8) & 0xFF, (len >> 16) & 0xFF, (len >> 24) & 0xFF,
        len & 0xFF, (len >> 8) & 0xFF, (len >> 16) & 0xFF, (len >> 24) & 0xFF
      ];

      pcapBytes.push(...packetHeader, ...bytes);
    });

    return new Uint8Array(pcapBytes);
  }

  return {
    LINK_FUNCTION_CODES,
    APP_FUNCTION_CODES,
    CROB_OP_TYPES,
    CROB_ACTION,
    IIN_BITS,
    crc16Dnp,
    crc32,
    ipChecksum,
    tcpChecksum,
    bytesToHex,
    hexToBytes,
    buildFt3Frame,
    encodeCrob,
    buildApdu,
    diagnoseIin,
    dissectFt3Frame,
    assembleEthernetTcpFrame,
    generatePcap
  };
});
