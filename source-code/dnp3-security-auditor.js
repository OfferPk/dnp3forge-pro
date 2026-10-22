/**
 * DNP3Forge Pro - NERC CIP & IEEE 1815-2012 Zero-Trust Security Auditor (v1.0.0)
 * Evaluates 10 Critical Electrical Substation OT / SCADA Cybersecurity Controls.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.DNP3SecurityAuditor = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const AUDIT_RULES = [
    {
      id: 'SAV5_AUTH',
      name: 'IEEE 1815 SAv5 Secure Authentication',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.secureAuthentication === 'SAv5' || config.secureAuthentication === 'HMAC_SHA256' || config.secureAuthentication === 'AES_GMAC') {
          return { score: 10, status: 'PASS', finding: 'IEEE Std 1815-2012 SAv5 cryptographic challenge-response authentication active.' };
        }
        if (config.secureAuthentication === 'SAv2') {
          return { score: 4, status: 'WARN', finding: 'Legacy SAv2 active. Lacks modern key derivation and symmetric MAC hardening.' };
        }
        return { score: 0, status: 'CRITICAL', finding: 'Secure Authentication DISABLED. Vulnerable to rogue command injection & replay attacks.' };
      }
    },
    {
      id: 'TRANSPORT_ENCRYPTION',
      name: 'Transport Layer Security / IPsec Tunneling',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.transportSecurity === 'TLS_1_3' || config.transportSecurity === 'IPsec_ESP') {
          return { score: 10, status: 'PASS', finding: 'DNP3 TCP 20000 traffic encapsulated in high-assurance TLS 1.3 / IPsec tunnel.' };
        }
        if (config.transportSecurity === 'TLS_1_2') {
          return { score: 8, status: 'PASS', finding: 'TLS 1.2 encapsulation active for DNP3 TCP port 20000.' };
        }
        return { score: 0, status: 'CRITICAL', finding: 'Cleartext TCP port 20000 exposed without cryptographic transport encapsulation.' };
      }
    },
    {
      id: 'SBO_ENFORCEMENT',
      name: 'Select-Before-Operate (SBO) Relay Enforcement',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.enforceSBO === true && config.allowDirectOperateBreakers === false) {
          return { score: 10, status: 'PASS', finding: 'Two-step Select-Before-Operate (SBO) strictly mandated for all breaker Trip/Close points.' };
        }
        if (config.enforceSBO === true) {
          return { score: 6, status: 'WARN', finding: 'SBO enabled, but Direct Operate is permitted on some output points.' };
        }
        return { score: 0, status: 'CRITICAL', finding: 'Direct Operate allowed on high-voltage circuit breakers. High risk of inadvertent tripping.' };
      }
    },
    {
      id: 'UNSOL_FLOOD_CAPS',
      name: 'Unsolicited Response Storm & Thundering Herd Controls',
      maxPoints: 10,
      evaluate: (config) => {
        const holdoff = parseInt(config.unsolicitedHoldoffMs, 10) || 0;
        const maxRetries = parseInt(config.unsolicitedMaxRetries, 10) || 0;
        if (holdoff >= 500 && maxRetries > 0 && maxRetries <= 5) {
          return { score: 10, status: 'PASS', finding: `Unsolicited backoff configured (Holdoff: ${holdoff}ms, Max Retries: ${maxRetries}).` };
        }
        if (holdoff > 0) {
          return { score: 5, status: 'WARN', finding: 'Unsolicited response backoff parameters partially configured.' };
        }
        return { score: 0, status: 'HIGH', finding: 'No unsolicited response rate-limiting. Vulnerable to storm exhaustion during SCADA restart.' };
      }
    },
    {
      id: 'CROB_RBAC',
      name: 'Control Relay (CROB) Role-Based Access Control',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.crobAccessControl === 'StrictRBAC' || config.crobRoleRequired === true) {
          return { score: 10, status: 'PASS', finding: 'CROB execution restricted to authenticated Dispatch Operator credentials.' };
        }
        return { score: 0, status: 'CRITICAL', finding: 'Unrestricted CROB execution. Any connected host can trigger relay closures.' };
      }
    },
    {
      id: 'LINK_ADDR_WHITELIST',
      name: 'Link Address Whitelisting & Spoof Protection',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.whitelistLinkAddresses === true) {
          return { score: 10, status: 'PASS', finding: 'Strict Destination/Source link address pair validation active.' };
        }
        return { score: 0, status: 'HIGH', finding: 'Promiscuous link address acceptance. Vulnerable to DNP3 address spoofing.' };
      }
    },
    {
      id: 'BROADCAST_PROTECTION',
      name: 'Broadcast Address (0xFFFF) Write/Operate Prohibition',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.blockBroadcastWriteOperate === true) {
          return { score: 10, status: 'PASS', finding: 'Write, Operate, and Restart commands to Broadcast (0xFFFF) strictly rejected.' };
        }
        return { score: 0, status: 'CRITICAL', finding: 'Broadcast address accepts control commands. Susceptible to catastrophic multi-IED outage.' };
      }
    },
    {
      id: 'REPLAY_CHALLENGE',
      name: 'Anti-Replay Challenge Sequence & Session Key Expiry',
      maxPoints: 10,
      evaluate: (config) => {
        const keyLifetimeMin = parseInt(config.sessionKeyLifetimeMinutes, 10) || 0;
        if (keyLifetimeMin > 0 && keyLifetimeMin <= 15 && config.antiReplayEnabled === true) {
          return { score: 10, status: 'PASS', finding: `Strict anti-replay window with ${keyLifetimeMin}-min session key rotation.` };
        }
        if (config.antiReplayEnabled === true) {
          return { score: 6, status: 'WARN', finding: `Anti-replay active, but session key lifetime is extended (${keyLifetimeMin} mins).` };
        }
        return { score: 0, status: 'HIGH', finding: 'Anti-replay verification disabled. Captures can be replayed to trigger relay actions.' };
      }
    },
    {
      id: 'REMOTE_RESTART_HARDENING',
      name: 'Remote Restart (Cold/Warm Restart 0x0E/0x0F) Hardening',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.disableRemoteRestart === true || config.requireElevatedRestartAuth === true) {
          return { score: 10, status: 'PASS', finding: 'Cold Restart (0x0E) and Warm Restart (0x0F) disabled or require administrative key.' };
        }
        return { score: 0, status: 'HIGH', finding: 'Unauthenticated remote reboot commands enabled. Vulnerable to forced RTU reset loops.' };
      }
    },
    {
      id: 'DPI_MICROSEGMENTATION',
      name: 'Substation Microsegmentation & Suricata DNP3 DPI',
      maxPoints: 10,
      evaluate: (config) => {
        if (config.substationSegmentation === true && config.suricataDnp3Dpi === true) {
          return { score: 10, status: 'PASS', finding: 'Isolated on Substation Bay OT VLAN with Suricata DNP3 parser inspecting port 20000.' };
        }
        if (config.substationSegmentation === true) {
          return { score: 7, status: 'PASS', finding: 'Subnet VLAN isolation active, but Deep Packet Inspection (DPI) is disabled.' };
        }
        return { score: 0, status: 'CRITICAL', finding: 'Substation network unsegmented or routable from corporate WAN.' };
      }
    }
  ];

  function auditConfiguration(config) {
    let totalScore = 0;
    const findings = [];

    AUDIT_RULES.forEach(rule => {
      const result = rule.evaluate(config);
      totalScore += result.score;
      findings.push({
        id: rule.id,
        name: rule.name,
        score: result.score,
        maxScore: rule.maxPoints,
        status: result.status,
        finding: result.finding
      });
    });

    let grade = 'F';
    if (totalScore >= 95) grade = 'A+';
    else if (totalScore >= 90) grade = 'A';
    else if (totalScore >= 80) grade = 'B';
    else if (totalScore >= 70) grade = 'C';
    else if (totalScore >= 60) grade = 'D';

    const passedCiGate = totalScore >= 80;

    return {
      totalScore,
      maxScore: 100,
      grade,
      passedCiGate,
      findings
    };
  }

  const PRESETS = {
    TRANSMISSION_SUBSTATION: {
      name: '500kV High-Voltage Transmission Substation (NERC CIP High)',
      secureAuthentication: 'SAv5',
      transportSecurity: 'IPsec_ESP',
      enforceSBO: true,
      allowDirectOperateBreakers: false,
      unsolicitedHoldoffMs: 1000,
      unsolicitedMaxRetries: 3,
      crobAccessControl: 'StrictRBAC',
      crobRoleRequired: true,
      whitelistLinkAddresses: true,
      blockBroadcastWriteOperate: true,
      antiReplayEnabled: true,
      sessionKeyLifetimeMinutes: 10,
      disableRemoteRestart: true,
      requireElevatedRestartAuth: true,
      substationSegmentation: true,
      suricataDnp3Dpi: true
    },
    DISTRIBUTION_FEEDER: {
      name: 'Medium-Voltage Distribution Feeder RTU (NERC CIP Medium)',
      secureAuthentication: 'SAv5',
      transportSecurity: 'TLS_1_2',
      enforceSBO: true,
      allowDirectOperateBreakers: false,
      unsolicitedHoldoffMs: 500,
      unsolicitedMaxRetries: 5,
      crobAccessControl: 'StrictRBAC',
      crobRoleRequired: true,
      whitelistLinkAddresses: true,
      blockBroadcastWriteOperate: true,
      antiReplayEnabled: true,
      sessionKeyLifetimeMinutes: 30,
      disableRemoteRestart: false,
      requireElevatedRestartAuth: true,
      substationSegmentation: true,
      suricataDnp3Dpi: false
    },
    VULNERABLE_LEGACY_RTU: {
      name: 'Vulnerable Legacy Substation RTU (Unauthenticated)',
      secureAuthentication: 'None',
      transportSecurity: 'Cleartext_TCP',
      enforceSBO: false,
      allowDirectOperateBreakers: true,
      unsolicitedHoldoffMs: 0,
      unsolicitedMaxRetries: 0,
      crobAccessControl: 'None',
      crobRoleRequired: false,
      whitelistLinkAddresses: false,
      blockBroadcastWriteOperate: false,
      antiReplayEnabled: false,
      sessionKeyLifetimeMinutes: 0,
      disableRemoteRestart: false,
      requireElevatedRestartAuth: false,
      substationSegmentation: false,
      suricataDnp3Dpi: false
    }
  };

  return {
    AUDIT_RULES,
    auditConfiguration,
    PRESETS
  };
});
