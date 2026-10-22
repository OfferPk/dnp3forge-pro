/**
 * DNP3Forge Pro - Web Application Controller (v1.0.0)
 * Binds UI Controls to Protocol Engine, CROB Packer, IIN Diagnoser, Auditor & Synthesizer.
 */

document.addEventListener('DOMContentLoaded', () => {
  const engine = window.DNP3ProtocolEngine;
  const auditor = window.DNP3SecurityAuditor;
  const synth = window.DNP3ConfigSynthesizer;

  // --- Tab Navigation ---
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add('active');
    });
  });

  // --- 1. Wireframe Studio Controller ---
  const studioFuncSelect = document.getElementById('studioFuncSelect');
  const studioDestInput = document.getElementById('studioDestInput');
  const studioSrcInput = document.getElementById('studioSrcInput');
  const studioSeqInput = document.getElementById('studioSeqInput');
  const studioRawHex = document.getElementById('studioRawHex');
  const studioDissected = document.getElementById('studioDissected');
  const downloadPcapBtn = document.getElementById('downloadPcapBtn');

  let currentFrameObj = null;

  function updateStudioFrame() {
    const funcCode = parseInt(studioFuncSelect.value, 16);
    const dest = parseInt(studioDestInput.value, 10) || 1;
    const src = parseInt(studioSrcInput.value, 10) || 2;
    const seq = parseInt(studioSeqInput.value, 10) || 1;

    let objectsPayload = [];
    if (funcCode === engine.APP_FUNCTION_CODES.READ) {
      // Read Class 0, 1, 2, 3 objects
      objectsPayload = [60, 1, 6, 60, 2, 6, 60, 3, 6, 60, 4, 6];
    } else if (funcCode === engine.APP_FUNCTION_CODES.SELECT || funcCode === engine.APP_FUNCTION_CODES.OPERATE || funcCode === engine.APP_FUNCTION_CODES.DIRECT_OPERATE) {
      // Object Group 12 (CROB), Var 1, Qualifier 0x17 (1-octet index, 1-octet qty)
      // Index 0, CROB: Trip Pulse On
      const crobBytes = engine.encodeCrob({ opType: 1, action: 2, count: 1, onTime: 100, offTime: 100, status: 0 });
      objectsPayload = [12, 1, 0x17, 1, 0, ...crobBytes];
    }

    const apdu = engine.buildApdu({
      transportSeq: seq,
      appSeq: seq,
      funcCode: funcCode,
      objectsPayload: objectsPayload
    });

    const ft3 = engine.buildFt3Frame(apdu, { dest, src });

    currentFrameObj = engine.assembleEthernetTcpFrame(ft3, {
      srcIp: '10.100.1.50',
      dstIp: '10.100.1.100',
      srcPort: 49152,
      dstPort: 20000
    });

    studioRawHex.textContent = engine.bytesToHex(currentFrameObj.fullFrameWithFcs);

    const dissected = engine.dissectFt3Frame(ft3);
    studioDissected.textContent = JSON.stringify(dissected, null, 2);
  }

  [studioFuncSelect, studioDestInput, studioSrcInput, studioSeqInput].forEach(el => {
    if (el) el.addEventListener('input', updateStudioFrame);
  });

  if (downloadPcapBtn) {
    downloadPcapBtn.addEventListener('click', () => {
      if (!currentFrameObj) return;
      const pcapBytes = engine.generatePcap([currentFrameObj]);
      const blob = new Blob([pcapBytes], { type: 'application/vnd.tcpdump.pcap' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `dnp3forge-${studioFuncSelect.options[studioFuncSelect.selectedIndex].text.toLowerCase().replace(/[^a-z0-9]/g, '-')}.pcap`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });
  }

  // --- 2. CROB Relay Packer Controller ---
  const crobActionSelect = document.getElementById('crobActionSelect');
  const crobOpTypeSelect = document.getElementById('crobOpTypeSelect');
  const crobCountInput = document.getElementById('crobCountInput');
  const crobOnTimeInput = document.getElementById('crobOnTimeInput');
  const crobOffTimeInput = document.getElementById('crobOffTimeInput');
  const crobHexOutput = document.getElementById('crobHexOutput');
  const crobParsedOutput = document.getElementById('crobParsedOutput');

  function updateCrobPacker() {
    const action = parseInt(crobActionSelect.value, 10);
    const opType = parseInt(crobOpTypeSelect.value, 10);
    const count = parseInt(crobCountInput.value, 10) || 1;
    const onTime = parseInt(crobOnTimeInput.value, 10) || 100;
    const offTime = parseInt(crobOffTimeInput.value, 10) || 100;

    const bytes = engine.encodeCrob({ action, opType, count, onTime, offTime, status: 0 });
    crobHexOutput.textContent = engine.bytesToHex(bytes);

    const controlCode = bytes[0];
    const actionName = (controlCode >> 6) === 1 ? 'Close' : ((controlCode >> 6) === 2 ? 'Trip' : 'NUL');
    const opNames = ['NUL', 'Pulse On', 'Pulse Off', 'Latch On', 'Latch Off'];
    const opName = opNames[controlCode & 0x0F] || 'Unknown';

    crobParsedOutput.textContent = JSON.stringify({
      rawControlCode: `0x${controlCode.toString(16).padStart(2, '0').toUpperCase()}`,
      action: actionName,
      operationType: opName,
      count: count,
      onTimeMs: onTime,
      offTimeMs: offTime,
      status: '0x00 (SUCCESS / REQUEST_ACCEPTED)',
      totalLengthBytes: bytes.length
    }, null, 2);
  }

  [crobActionSelect, crobOpTypeSelect, crobCountInput, crobOnTimeInput, crobOffTimeInput].forEach(el => {
    if (el) el.addEventListener('input', updateCrobPacker);
  });

  // --- 3. IIN Diagnoser Controller ---
  const iinHexInput = document.getElementById('iinHexInput');
  const iinRawDisplay = document.getElementById('iinRawDisplay');
  const iinFlagsList = document.getElementById('iinFlagsList');

  function updateIinDiagnoser() {
    const valStr = (iinHexInput.value || '').trim();
    let val = 0;
    if (valStr.startsWith('0x') || valStr.startsWith('0X')) {
      val = parseInt(valStr, 16) || 0;
    } else {
      val = parseInt(valStr, 10) || 0;
    }

    const iin1 = val & 0xFF;
    const iin2 = (val >> 8) & 0xFF;
    const diag = engine.diagnoseIin(iin1, iin2);

    iinRawDisplay.textContent = `IIN Word: ${diag.iinRaw} (IIN1: ${diag.iin1}, IIN2: ${diag.iin2}) — ${diag.activeFlagsCount} Active Indication(s)`;

    iinFlagsList.innerHTML = '';
    if (diag.flags.length === 0) {
      iinFlagsList.innerHTML = '<div style="color: var(--text-dim); padding: 0.5rem;">No internal indication flags active (Normal state).</div>';
    } else {
      diag.flags.forEach(f => {
        const item = document.createElement('div');
        item.className = 'audit-item';
        const color = f.severity === 'CRITICAL' ? 'score-fail' : (f.severity === 'WARN' ? 'score-warn' : 'score-pass');
        item.innerHTML = `
          <div class="audit-meta">
            <div class="audit-title" style="color: #fff;">${f.name} [IIN${f.octet} Bit ${f.bit}]</div>
            <div class="audit-desc">${f.description}</div>
          </div>
          <div class="audit-score ${color}">[${f.severity}]</div>
        `;
        iinFlagsList.appendChild(item);
      });
    }
  }

  if (iinHexInput) {
    iinHexInput.addEventListener('input', updateIinDiagnoser);
  }

  // --- 4. NERC CIP Security Auditor Controller ---
  const auditPresetSelect = document.getElementById('auditPresetSelect');
  const auditScoreDisplay = document.getElementById('auditTotalScore');
  const auditGradeDisplay = document.getElementById('auditGrade');
  const auditFindingsContainer = document.getElementById('auditFindingsList');

  // Input toggles
  const auditSav5 = document.getElementById('auditSav5');
  const auditTransportSec = document.getElementById('auditTransportSec');
  const auditSbo = document.getElementById('auditSbo');
  const auditUnsolHoldoff = document.getElementById('auditUnsolHoldoff');
  const auditCrobRbac = document.getElementById('auditCrobRbac');
  const auditLinkWhitelist = document.getElementById('auditLinkWhitelist');
  const auditBlockBroadcast = document.getElementById('auditBlockBroadcast');
  const auditAntiReplay = document.getElementById('auditAntiReplay');
  const auditKeyLifetime = document.getElementById('auditKeyLifetime');
  const auditDisableRestart = document.getElementById('auditDisableRestart');
  const auditSegmentation = document.getElementById('auditSegmentation');

  function runAuditEvaluation() {
    const config = {
      secureAuthentication: auditSav5.value,
      transportSecurity: auditTransportSec.value,
      enforceSBO: auditSbo.checked,
      allowDirectOperateBreakers: !auditSbo.checked,
      unsolicitedHoldoffMs: parseInt(auditUnsolHoldoff.value, 10) || 0,
      unsolicitedMaxRetries: 3,
      crobAccessControl: auditCrobRbac.checked ? 'StrictRBAC' : 'None',
      crobRoleRequired: auditCrobRbac.checked,
      whitelistLinkAddresses: auditLinkWhitelist.checked,
      blockBroadcastWriteOperate: auditBlockBroadcast.checked,
      antiReplayEnabled: auditAntiReplay.checked,
      sessionKeyLifetimeMinutes: parseInt(auditKeyLifetime.value, 10) || 0,
      disableRemoteRestart: auditDisableRestart.checked,
      requireElevatedRestartAuth: auditDisableRestart.checked,
      substationSegmentation: auditSegmentation.checked,
      suricataDnp3Dpi: auditSegmentation.checked
    };

    const result = auditor.auditConfiguration(config);

    auditScoreDisplay.textContent = `${result.totalScore} / 100`;
    auditGradeDisplay.textContent = `Grade: ${result.grade}`;
    auditGradeDisplay.className = `score-badge-large grade-${result.grade.charAt(0)}`;

    auditFindingsContainer.innerHTML = '';
    result.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = 'audit-item';
      const statusClass = f.status === 'PASS' ? 'score-pass' : (f.status === 'WARN' ? 'score-warn' : 'score-fail');
      item.innerHTML = `
        <div class="audit-meta">
          <div class="audit-title">${f.name}</div>
          <div class="audit-desc">${f.finding}</div>
        </div>
        <div class="audit-score ${statusClass}">
          ${f.score}/${f.maxScore} pts [${f.status}]
        </div>
      `;
      auditFindingsContainer.appendChild(item);
    });
  }

  function applyPreset(presetKey) {
    const p = auditor.PRESETS[presetKey];
    if (!p) return;
    auditSav5.value = p.secureAuthentication;
    auditTransportSec.value = p.transportSecurity;
    auditSbo.checked = p.enforceSBO;
    auditUnsolHoldoff.value = p.unsolicitedHoldoffMs;
    auditCrobRbac.checked = p.crobRoleRequired;
    auditLinkWhitelist.checked = p.whitelistLinkAddresses;
    auditBlockBroadcast.checked = p.blockBroadcastWriteOperate;
    auditAntiReplay.checked = p.antiReplayEnabled;
    auditKeyLifetime.value = p.sessionKeyLifetimeMinutes;
    auditDisableRestart.checked = p.disableRemoteRestart;
    auditSegmentation.checked = p.substationSegmentation;
    runAuditEvaluation();
  }

  if (auditPresetSelect) {
    auditPresetSelect.addEventListener('change', () => applyPreset(auditPresetSelect.value));
  }

  [auditSav5, auditTransportSec, auditSbo, auditUnsolHoldoff, auditCrobRbac, auditLinkWhitelist, auditBlockBroadcast, auditAntiReplay, auditKeyLifetime, auditDisableRestart, auditSegmentation].forEach(el => {
    if (el) el.addEventListener('change', runAuditEvaluation);
    if (el) el.addEventListener('input', runAuditEvaluation);
  });

  // --- 5. Code Synthesizer Controller ---
  const synthPlatformSelect = document.getElementById('synthPlatformSelect');
  const synthCodeOutput = document.getElementById('synthCodeOutput');

  function updateSynthesizedCode() {
    const plat = synthPlatformSelect.value;
    const config = {
      ip: '10.100.1.100',
      port: 20000,
      dest: parseInt(studioDestInput ? studioDestInput.value : 1, 10) || 1,
      src: parseInt(studioSrcInput ? studioSrcInput.value : 2, 10) || 2
    };

    let code = '';
    if (plat === 'python') code = synth.generatePythonOpendnp3(config);
    else if (plat === 'cpp') code = synth.generateCppOpendnp3(config);
    else if (plat === 'firewall') code = synth.generateSuricataAndFirewall(config);

    synthCodeOutput.textContent = code;
  }

  if (synthPlatformSelect) {
    synthPlatformSelect.addEventListener('change', updateSynthesizedCode);
  }

  // Initial update
  updateStudioFrame();
  updateCrobPacker();
  updateIinDiagnoser();
  applyPreset('TRANSMISSION_SUBSTATION');
  updateSynthesizedCode();
});
