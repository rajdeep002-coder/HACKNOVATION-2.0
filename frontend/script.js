    // ==================== DATA STRUCTURES ====================
    
    // Initialize all state variables first
    let attackLogs = [];
    let incidentCases = [];
    let caseCounter = 1000;
    let evidenceCounter = 5000;

    const MITRE_MAPPING = {
      'sqli': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      'xss': { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
      'bruteforce': { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access' },
      'scan': { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance' },
      'pathtraversal': { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
      'ssti': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' }
    };

    const SEVERITY_WEIGHTS = {
      'critical': 10,
      'high': 7,
      'medium': 4,
      'low': 2
    };

    const ATTACK_SIGNATURES = [
      { pattern: /('|")?\s*(or|and)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, type: 'sqli', severity: 'critical', confidence: 95 },
      { pattern: /union\s+(all\s+)?select/i, type: 'sqli', severity: 'critical', confidence: 98 },
      { pattern: /;\s*(drop|delete|update|insert|truncate)/i, type: 'sqli', severity: 'critical', confidence: 99 },
      { pattern: /<\s*script[^>]*>/i, type: 'xss', severity: 'high', confidence: 95 },
      { pattern: /on\w+\s*=/i, type: 'xss', severity: 'high', confidence: 85 },
      { pattern: /javascript:/i, type: 'xss', severity: 'high', confidence: 90 },
      { pattern: /\.\./i, type: 'pathtraversal', severity: 'high', confidence: 80 },
      { pattern: /\/etc\/passwd/i, type: 'pathtraversal', severity: 'critical', confidence: 95 },
      { pattern: /constructor\s*\(/i, type: 'ssti', severity: 'critical', confidence: 90 },
      { pattern: /\{\{.*\}\}/, type: 'ssti', severity: 'high', confidence: 75 }
    ];

    // ==================== UTILITY FUNCTIONS ====================
    
    function generateIP() {
      const patterns = [
        () => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        () => `${Math.floor(Math.random() * 10) + 45}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
        () => `${Math.floor(Math.random() * 50) + 100}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`
      ];
      return patterns[Math.floor(Math.random() * patterns.length)]();
    }

    function generateHash() {
      const chars = 'abcdef0123456789';
      let hash = '';
      for (let i = 0; i < 64; i++) {
        hash += chars[Math.floor(Math.random() * chars.length)];
      }
      return hash;
    }

    function formatTimestamp(date) {
      return date.toISOString().replace('T', ' ').substring(0, 19);
    }

    function calculateRiskScore(severity, confidence) {
      const weight = SEVERITY_WEIGHTS[severity] || 2;
      return Math.round((weight * confidence) / 10);
    }

    function generateCaseId() {
      caseCounter++;
      return `CASE-${new Date().getFullYear()}-${String(caseCounter).padStart(4, '0')}`;
    }

    function generateEvidenceId() {
      evidenceCounter++;
      return `EVD-${String(evidenceCounter).padStart(4, '0')}`;
    }

    // ==================== DETECTION ENGINE ====================
    
    function analyzePayload(payload) {
      const results = [];
      
      for (const sig of ATTACK_SIGNATURES) {
        if (sig.pattern.test(payload)) {
          results.push({
            type: sig.type,
            severity: sig.severity,
            confidence: sig.confidence,
            matched: payload.match(sig.pattern)?.[0] || 'pattern'
          });
        }
      }

      if (results.length === 0) {
        return null;
      }

      // Return highest severity result
      return results.sort((a, b) => {
        const order = ['critical', 'high', 'medium', 'low'];
        return order.indexOf(a.severity) - order.indexOf(b.severity);
      })[0];
    }

    function createAttackLog(sourceIP, attackType, severity, confidence, payload) {
      const timestamp = new Date();
      const mitre = MITRE_MAPPING[attackType];
      const riskScore = calculateRiskScore(severity, confidence);

      const log = {
        id: Date.now(),
        timestamp: formatTimestamp(timestamp),
        ip: sourceIP,
        type: attackType,
        severity: severity,
        confidence: confidence,
        mitre: mitre,
        riskScore: riskScore,
        payload: payload.substring(0, 100),
        blocked: severity === 'critical' || severity === 'high'
      };

      //BACKEND
      console.log("LOG:",log);
      sendLogToBackend(log);

      attackLogs.unshift(log);

      // Auto-create incident case for critical or high confidence
      if (severity === 'critical' || confidence > 80) {
        createIncidentCase(log);
      }

      return log;
    }

    function createIncidentCase(triggerLog) {
      const relatedLogs = attackLogs.filter(log => 
        log.ip === triggerLog.ip && log.id !== triggerLog.id
      ).slice(0, 5);

      const caseData = {
        id: generateCaseId(),
        evidenceId: generateEvidenceId(),
        hash: generateHash(),
        timestamp: new Date(),
        triggerLog: triggerLog,
        relatedLogs: relatedLogs,
        status: 'open',
        riskScore: triggerLog.riskScore,
        mitre: triggerLog.mitre
      };

      incidentCases.unshift(caseData);
      updateCasesUI();
      updateReportSelect();
      updateDashboardStats();
    }

    // ==================== UI UPDATE FUNCTIONS ====================
    
    function updateDashboardStats() {
      const total = 2847 + attackLogs.length;
      const blocked = attackLogs.filter(l => l.blocked).length + 956;
      const allowed = total - blocked;

      document.getElementById('stat-total').textContent = total.toLocaleString();
      document.getElementById('stat-blocked').textContent = blocked.toLocaleString();
      document.getElementById('stat-allowed').textContent = allowed.toLocaleString();
      document.getElementById('stat-cases').textContent = incidentCases.filter(c => c.status !== 'closed').length;

      // Update severity counts
      const sevCounts = { critical: 23, high: 89, medium: 234, low: 610 };
      attackLogs.forEach(log => {
        sevCounts[log.severity] = (sevCounts[log.severity] || 0) + 1;
      });

      document.getElementById('sev-critical').textContent = sevCounts.critical;
      document.getElementById('sev-high').textContent = sevCounts.high;
      document.getElementById('sev-medium').textContent = sevCounts.medium;
      document.getElementById('sev-low').textContent = sevCounts.low;

      // Update attack type counts
      const typeCounts = { sqli: 342, xss: 287, bruteforce: 156, scan: 171 };
      attackLogs.forEach(log => {
        typeCounts[log.type] = (typeCounts[log.type] || 0) + 1;
      });

      document.getElementById('count-sqli').textContent = typeCounts.sqli;
      document.getElementById('count-xss').textContent = typeCounts.xss;
      document.getElementById('count-brute').textContent = typeCounts.bruteforce;
      document.getElementById('count-scan').textContent = typeCounts.scan;

      // Update case stats
      document.getElementById('case-open').textContent = incidentCases.filter(c => c.status === 'open').length;
      document.getElementById('case-investigating').textContent = incidentCases.filter(c => c.status === 'investigating').length;
      document.getElementById('case-closed').textContent = incidentCases.filter(c => c.status === 'closed').length;
    }

    function updateLiveFeed() {
      const feed = document.getElementById('liveFeed');
      const recentAttacks = attackLogs.slice(0, 8);

      feed.innerHTML = recentAttacks.map(attack => `
        <div class="attack-item ${attack.severity}">
          <div class="flex-shrink-0">
            ${getAttackIcon(attack.type)}
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              <span class="font-medium">${attack.type.toUpperCase()}</span>
              <span class="badge badge-${attack.severity}">${attack.severity}</span>
            </div>
            <div class="text-xs text-gray-500 font-mono truncate">${attack.ip}</div>
          </div>
          <div class="text-xs text-gray-500">${attack.timestamp.split(' ')[1]}</div>
        </div>
      `).join('');
    }

    function getAttackIcon(type) {
      const icons = {
        'sqli': `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>`,
        'xss': `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--high)" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`,
        'bruteforce': `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--warning)" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
        'scan': `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
        'pathtraversal': `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
        'ssti': `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--critical)" stroke-width="2"><template></template><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6v6H9z"/></svg>`
      };
      return icons[type] || icons['scan'];
    }

    function updateLogsTable() {
      const tbody = document.getElementById('logsTableBody');
      const search = document.getElementById('logSearch').value.toLowerCase();
      const severityFilter = document.getElementById('logSeverityFilter').value;
      const typeFilter = document.getElementById('logTypeFilter').value;

      let filteredLogs = attackLogs;
      console.log("LOGS:",filteredLogs);

      if (search) {
        filteredLogs = filteredLogs.filter(log => 
          log.ip.includes(search) || log.type.includes(search)
        );
      }

      if (severityFilter !== 'all') {
        filteredLogs = filteredLogs.filter(log => log.severity === severityFilter);
      }

      if (typeFilter !== 'all') {
        filteredLogs = filteredLogs.filter(log => log.type === typeFilter);
      }

      tbody.innerHTML = filteredLogs.slice(0, 50).map(log => `
        <tr>
          <td class="font-mono text-xs">${log.timestamp}</td>
          <td class="font-mono">${log.ip}</td>
          <td>
            <span class="flex items-center gap-2">
              ${getAttackIcon(log.type)}
              ${log.type.toUpperCase()}
            </span>
          </td>
          <td><span class="badge badge-${log.severity}">${log.severity}</span></td>
          <td>
            <div class="flex items-center gap-2">
              <div class="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
                <div class="h-full rounded-full ${log.confidence > 80 ? 'bg-red-500' : log.confidence > 60 ? 'bg-yellow-500' : 'bg-green-500'}" style="width: ${log.confidence}%"></div>
              </div>
              <span class="font-mono text-xs">${log.confidence}%</span>
            </div>
          </td>
          <td><span class="mitre-badge text-xs">${log.mitre?.id || '-'}</span></td>
          <td>
            <span class="badge ${log.blocked ? 'badge-critical' : 'badge-success'}">${log.blocked ? 'Blocked' : 'Logged'}</span>
          </td>
        </tr>
      `).join('');
    }

    function updateCasesUI() {
      const container = document.getElementById('casesList');
      const statusFilter = document.getElementById('caseStatusFilter').value;

      let filteredCases = incidentCases;
      if (statusFilter !== 'all') {
        filteredCases = filteredCases.filter(c => c.status === statusFilter);
      }

      container.innerHTML = filteredCases.map(caseData => `
        <div class="case-card">
          <div class="flex items-start justify-between mb-4">
            <div>
              <div class="flex items-center gap-3 mb-1">
                <span class="font-mono font-bold text-lg">${caseData.id}</span>
                <span class="badge badge-${caseData.triggerLog.severity}">${caseData.triggerLog.severity}</span>
              </div>
              <div class="text-sm text-gray-400">Evidence: ${caseData.evidenceId}</div>
            </div>
            <div class="flex items-center gap-2">
              <span class="status-dot ${caseData.status}"></span>
              <select class="input text-xs w-32" data-case-id="${caseData.id}" onchange="updateCaseStatus('${caseData.id}', this.value)">
                <option value="open" ${caseData.status === 'open' ? 'selected' : ''}>Open</option>
                <option value="investigating" ${caseData.status === 'investigating' ? 'selected' : ''}>Investigating</option>
                <option value="closed" ${caseData.status === 'closed' ? 'selected' : ''}>Closed</option>
              </select>
            </div>
          </div>
          
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <div class="text-gray-500 text-xs">Attack Type</div>
              <div class="font-medium">${caseData.triggerLog.type.toUpperCase()}</div>
            </div>
            <div>
              <div class="text-gray-500 text-xs">Source IP</div>
              <div class="font-mono">${caseData.triggerLog.ip}</div>
            </div>
            <div>
              <div class="text-gray-500 text-xs">Risk Score</div>
              <div class="font-bold" style="color: ${caseData.riskScore > 80 ? 'var(--danger)' : caseData.riskScore > 50 ? 'var(--warning)' : 'var(--success)'}">${caseData.riskScore}/100</div>
            </div>
            <div>
              <div class="text-gray-500 text-xs">MITRE</div>
              <span class="mitre-badge">${caseData.mitre?.id || '-'}</span>
            </div>
          </div>

          <div class="mt-4 pt-4 border-t border-gray-700">
            <div class="text-xs text-gray-500 mb-2">Hash (SHA-256)</div>
            <div class="font-mono text-xs text-gray-400 break-all">${caseData.hash}</div>
          </div>
        </div>
      `).join('');
    }

    function updateCaseStatus(caseId, newStatus) {
      const caseData = incidentCases.find(c => c.id === caseId);
      if (caseData) {
        caseData.status = newStatus;
        updateDashboardStats();
      }
    }

    function updateReportSelect() {
      const select = document.getElementById('reportCaseSelect');
      select.innerHTML = '<option value="">Select a case...</option>' + 
        incidentCases.map(c => `<option value="${c.id}">${c.id} - ${c.triggerLog.type.toUpperCase()}</option>`).join('');
    }

    function generateReport(caseId) {
      const caseData = incidentCases.find(c => c.id === caseId);
      if (!caseData) return;

      // Evidence Summary
      document.getElementById('reportCaseId').textContent = caseData.id;
      document.getElementById('reportEvidenceId').textContent = caseData.evidenceId;
      document.getElementById('reportGenerated').textContent = formatTimestamp(new Date());
      document.getElementById('reportHash').textContent = caseData.hash.substring(0, 16) + '...';
      document.getElementById('reportRiskLevel').innerHTML = `<span class="badge badge-${caseData.triggerLog.severity}">${caseData.triggerLog.severity.toUpperCase()}</span>`;
      document.getElementById('reportLogsCount').textContent = (caseData.relatedLogs?.length || 0) + 1;

      // MITRE Mapping
      const mitreContainer = document.getElementById('mitreMapping');
      const mitre = caseData.mitre;
      if (mitre) {
        mitreContainer.innerHTML = `
          <div class="p-3 bg-gray-800 rounded-lg">
            <div class="flex items-center gap-2 mb-2">
              <span class="mitre-badge">${mitre.id}</span>
              <span class="font-medium">${mitre.name}</span>
            </div>
            <div class="text-sm text-gray-400">Tactic: ${mitre.tactic}</div>
          </div>
        `;
      }

      // Timeline
      const timelineContainer = document.getElementById('timeline');
      const allLogs = [caseData.triggerLog, ...(caseData.relatedLogs || [])].sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
      );

      timelineContainer.innerHTML = allLogs.map((log, i) => `
        <div class="timeline-item">
          <div class="text-xs text-gray-500 mb-1">${log.timestamp}</div>
          <div class="flex items-center gap-2">
            ${getAttackIcon(log.type)}
            <span class="font-medium">${log.type.toUpperCase()}</span>
            <span class="badge badge-${log.severity}">${log.severity}</span>
          </div>
          <div class="text-sm text-gray-400 mt-1">Source: ${log.ip}</div>
        </div>
      `).join('');

      // AI Summary
      const aiSummary = generateAISummary(caseData);
      document.getElementById('aiSummary').textContent = aiSummary;

      // Recommendations
      const recommendations = generateRecommendations(caseData.triggerLog.type);
      document.getElementById('recommendations').innerHTML = recommendations.map(rec => `
        <div class="recommendation">
          <svg class="recommendation-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 12l2 2 4-4"/>
            <circle cx="12" cy="12" r="10"/>
          </svg>
          <div>
            <div class="font-medium mb-1">${rec.title}</div>
            <div class="text-sm text-gray-400">${rec.description}</div>
          </div>
        </div>
      `).join('');
    }

    function generateAISummary(caseData) {
      const log = caseData.triggerLog;
      const templates = {
        'sqli': `Multiple high-severity SQL injection attempts were detected originating from ${log.ip}. The attack pattern suggests systematic exploitation targeting database interactions. Evidence indicates ${log.confidence}% confidence of malicious intent, consistent with MITRE ATT&CK technique T1190 (Exploit Public-Facing Application). The payloads detected demonstrate awareness of SQL syntax and attempt to manipulate backend queries for potential data extraction or authentication bypass. Immediate investigation of affected endpoints is recommended.`,
        
        'xss': `Cross-site scripting attacks have been identified from source ${log.ip} with ${log.confidence}% confidence. The malicious payloads are designed to execute arbitrary JavaScript in victim browsers, mapped to MITRE T1059 (Command and Scripting Interpreter). Analysis suggests this may be part of a broader client-side attack campaign. Session hijacking and credential theft are primary concerns. Input sanitization review is strongly advised.`,
        
        'bruteforce': `Automated brute force authentication attempts detected from ${log.ip}. The activity pattern indicates credential stuffing with ${log.confidence}% confidence, aligning with MITRE T1110 (Brute Force). Multiple username/password combinations were attempted in rapid succession. This suggests the attacker possesses leaked credential databases. Account lockout policies and MFA implementation should be verified.`,
        
        'pathtraversal': `Path traversal exploitation attempts identified from ${log.ip} targeting file system access. The attack aims to access sensitive files outside web root with ${log.confidence}% confidence, mapped to MITRE T1083 (File and Directory Discovery). Successful exploitation could lead to configuration disclosure or source code exposure. File access controls require immediate review.`,
        
        'ssti': `Server-side template injection attacks detected from ${log.ip} with ${log.confidence}% confidence. These payloads target template engines to achieve remote code execution, classified under MITRE T1190. The sophistication level indicates an advanced threat actor. Template rendering logic requires immediate security audit.`
      };

      return templates[log.type] || `Security incident detected from ${log.ip}. Attack type: ${log.type.toUpperCase()} with ${log.confidence}% confidence. Risk score: ${caseData.riskScore}/100. Review and remediation recommended.`;
    }

    function generateRecommendations(attackType) {
      const recs = {
        'sqli': [
          { title: 'Implement Parameterized Queries', description: 'Replace all dynamic SQL with prepared statements to prevent injection.' },
          { title: 'Input Validation Layer', description: 'Deploy strict input validation with allowlists for expected formats.' },
          { title: 'WAF Rules Update', description: 'Add specific SQLi detection rules for the identified attack patterns.' },
          { title: 'Database Permission Review', description: 'Ensure application uses least-privilege database accounts.' }
        ],
        'xss': [
          { title: 'Output Encoding', description: 'Implement context-aware output encoding for all user-controlled data.' },
          { title: 'Content Security Policy', description: 'Deploy strict CSP headers to mitigate script execution.' },
          { title: 'Input Sanitization', description: 'Add HTML sanitization for rich text inputs.' },
          { title: 'HttpOnly Cookies', description: 'Enable HttpOnly flag on session cookies.' }
        ],
        'bruteforce': [
          { title: 'Rate Limiting', description: 'Implement progressive delays for failed authentication attempts.' },
          { title: 'Multi-Factor Authentication', description: 'Enforce MFA for all user accounts.' },
          { title: 'Account Lockout Policy', description: 'Configure automatic lockout after 5 failed attempts.' },
          { title: 'CAPTCHA Integration', description: 'Add CAPTCHA challenges on login forms.' }
        ],
        'pathtraversal': [
          { title: 'Path Canonicalization', description: 'Use realpath() or equivalent to resolve and validate file paths.' },
          { title: 'Sandbox File Access', description: 'Restrict file operations to designated directories only.' },
          { title: 'Input Validation', description: 'Reject requests containing ../ or absolute paths.' }
        ],
        'ssti': [
          { title: 'Template Sandbox', description: 'Configure template engines to run in sandboxed mode.' },
          { title: 'Disable Dangerous Functions', description: 'Remove access to system functions within template context.' },
          { title: 'Input Allowlisting', description: 'Strictly validate template variable inputs.' }
        ]
      };

      return recs[attackType] || [
        { title: 'Security Review', description: 'Conduct thorough security assessment of affected systems.' },
        { title: 'Monitor Closely', description: 'Increase logging and monitoring for similar activities.' }
      ];
    }

    // ==================== INITIALIZATION ====================
    
    function initializeSampleData() {
      // Sample attack logs
      const sampleAttacks = [
        { ip: '45.33.32.156', type: 'sqli', severity: 'critical', confidence: 98 },
        { ip: '192.168.1.105', type: 'xss', severity: 'high', confidence: 92 },
        { ip: '10.0.0.45', type: 'bruteforce', severity: 'high', confidence: 87 },
        { ip: '172.16.0.88', type: 'scan', severity: 'medium', confidence: 75 },
        { ip: '203.0.113.42', type: 'sqli', severity: 'critical', confidence: 95 },
        { ip: '198.51.100.23', type: 'pathtraversal', severity: 'high', confidence: 88 }
      ];

      sampleAttacks.forEach(attack => {
        createAttackLog(attack.ip, attack.type, attack.severity, attack.confidence, 'sample payload');
      });

      // Sample incident cases
      incidentCases = [
        {
          id: 'CASE-2025-0001',
          evidenceId: 'EVD-0001',
          hash: generateHash(),
          timestamp: new Date(Date.now() - 3600000),
          triggerLog: { type: 'sqli', severity: 'critical', ip: '45.33.32.156', confidence: 98, riskScore: 98 },
          relatedLogs: [],
          status: 'open',
          riskScore: 98,
          mitre: MITRE_MAPPING['sqli']
        },
        {
          id: 'CASE-2025-0002',
          evidenceId: 'EVD-0002',
          hash: generateHash(),
          timestamp: new Date(Date.now() - 7200000),
          triggerLog: { type: 'xss', severity: 'high', ip: '192.168.1.105', confidence: 92, riskScore: 64 },
          relatedLogs: [],
          status: 'investigating',
          riskScore: 64,
          mitre: MITRE_MAPPING['xss']
        },
        {
          id: 'CASE-2025-0003',
          evidenceId: 'EVD-0003',
          hash: generateHash(),
          timestamp: new Date(Date.now() - 86400000),
          triggerLog: { type: 'bruteforce', severity: 'high', ip: '10.0.0.45', confidence: 87, riskScore: 61 },
          relatedLogs: [],
          status: 'closed',
          riskScore: 61,
          mitre: MITRE_MAPPING['bruteforce']
        }
      ];

      updateCasesUI();
      updateReportSelect();
      updateDashboardStats();
      updateLiveFeed();
      updateLogsTable();
      renderPieChart();
    }

    function renderPieChart() {
      const data = [
        { label: 'SQL Injection', value: 342, color: '#ef4444' },
        { label: 'XSS', value: 287, color: '#f97316' },
        { label: 'Brute Force', value: 156, color: '#eab308' },
        { label: 'Port Scan', value: 171, color: '#06b6d4' }
      ];

      const total = data.reduce((sum, d) => sum + d.value, 0);
      const pieChart = document.getElementById('pieChart');
      const legend = document.getElementById('pieLegend');

      // Create conic gradient
      let gradient = 'conic-gradient(';
      let currentAngle = 0;

      data.forEach((d, i) => {
        const angle = (d.value / total) * 360;
        gradient += `${d.color} ${currentAngle}deg ${currentAngle + angle}deg`;
        if (i < data.length - 1) gradient += ', ';
        currentAngle += angle;
      });
      gradient += ')';

      pieChart.style.background = gradient;

      legend.innerHTML = data.map(d => `
        <div class="pie-legend-item">
          <div class="pie-legend-dot" style="background: ${d.color}"></div>
          <span class="text-gray-400">${d.label}</span>
          <span class="font-mono ml-auto">${d.value}</span>
        </div>
      `).join('');
    }

    // ==================== EVENT HANDLERS ====================
    
    function setupEventHandlers() {
      // Navigation
      document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
          document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
          item.classList.add('active');

          document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
          document.getElementById(`page-${item.dataset.page}`).classList.add('active');
        });
      });

      // Mobile menu
      document.getElementById('menuToggle').addEventListener('click', () => {
        document.getElementById('sidebar').classList.toggle('open');
      });

      // Simulate attack
      document.getElementById('simulateBtn').addEventListener('click', () => {
        const types = ['sqli', 'xss', 'bruteforce', 'scan', 'pathtraversal', 'ssti'];
        const severities = ['critical', 'high', 'medium', 'low'];
        const type = types[Math.floor(Math.random() * types.length)];
        const severity = severities[Math.floor(Math.random() * severities.length)];
        const confidence = 60 + Math.floor(Math.random() * 40);

        createAttackLog(generateIP(), type, severity, confidence, 'simulated payload');
        updateDashboardStats();
        updateLiveFeed();
        updateLogsTable();
      });

      // Scanner analyze
      document.getElementById('analyzeBtn').addEventListener('click', () => {
        const body = document.getElementById('scanBody').value;
        const url = document.getElementById('scanUrl').value;
        const method = document.getElementById('scanMethod').value;
        const payload = body || url;

        if (!payload) {
          document.getElementById('scanResult').innerHTML = `
            <div class="scan-result safe">
              <div class="font-medium text-green-400 mb-2">No Payload Detected</div>
              <div class="text-sm">Enter a request body or URL parameters to analyze.</div>
            </div>
          `;
          return;
        }

        const result = analyzePayload(payload);
        const resultContainer = document.getElementById('scanResult');

        if (result) {
          const log = createAttackLog(generateIP(), result.type, result.severity, result.confidence, payload);
          resultContainer.innerHTML = `
            <div class="scan-result malicious">
              <div class="flex items-center gap-2 mb-3">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="2">
                  <circle cx="12" cy="12" r="10"/>
                  <line x1="15" y1="9" x2="9" y2="15"/>
                  <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
                <span class="font-bold text-red-400">MALICIOUS PAYLOAD DETECTED</span>
              </div>
              
              <div class="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <div class="text-xs text-gray-500 mb-1">Attack Type</div>
                  <div class="font-bold">${result.type.toUpperCase()}</div>
                </div>
                <div>
                  <div class="text-xs text-gray-500 mb-1">Severity</div>
                  <span class="badge badge-${result.severity}">${result.severity}</span>
                </div>
                <div>
                  <div class="text-xs text-gray-500 mb-1">Confidence</div>
                  <div class="font-mono">${result.confidence}%</div>
                </div>
                <div>
                  <div class="text-xs text-gray-500 mb-1">MITRE</div>
                  <span class="mitre-badge">${log.mitre?.id || '-'}</span>
                </div>
              </div>

              <div class="p-3 bg-gray-900 rounded text-xs font-mono break-all">
                <div class="text-gray-500 mb-1">Matched Pattern:</div>
                ${result.matched}
              </div>

              <div class="mt-3 text-xs text-gray-400">
                <span class="text-green-400">Logged</span> with ID ${log.id}
                ${log.blocked ? ' and <span class="text-red-400">blocked</span>' : ''}
              </div>
            </div>
          `;
          updateDashboardStats();
          updateLiveFeed();
          updateLogsTable();
        } else {
          resultContainer.innerHTML = `
            <div class="scan-result safe">
              <div class="flex items-center gap-2 mb-3">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                  <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                <span class="font-bold text-green-400">NO THREAT DETECTED</span>
              </div>
              <div class="text-sm text-gray-400">
                The payload did not match any known attack signatures. Manual review may be required for sophisticated or novel attack vectors.
              </div>
            </div>
          `;
        }
      });

      // Test payloads
      document.querySelectorAll('[data-payload]').forEach(btn => {
        btn.addEventListener('click', () => {
          document.getElementById('scanBody').value = btn.dataset.payload;
        });
      });

      // Log filters
      ['logSearch', 'logSeverityFilter', 'logTypeFilter'].forEach(id => {
        document.getElementById(id).addEventListener('input', updateLogsTable);
        document.getElementById(id).addEventListener('change', updateLogsTable);
      });

      // Export logs
      document.getElementById('exportLogsBtn').addEventListener('click', () => {
        const data = JSON.stringify(attackLogs, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `neuralshield-logs-${Date.now()}.json`;
        a.click();
      });

      // Clear logs
      document.getElementById('clearLogsBtn').addEventListener('click', () => {
        if (confirm('Clear all attack logs? This cannot be undone.')) {
          attackLogs = [];
          updateLogsTable();
          updateLiveFeed();
          updateDashboardStats();
        }
      });

      // Case status filter
      document.getElementById('caseStatusFilter').addEventListener('change', updateCasesUI);

      // Report case select
      document.getElementById('reportCaseSelect').addEventListener('change', (e) => {
        if (e.target.value) {
          generateReport(e.target.value);
        }
      });

      // Generate full report
      document.getElementById('generateReportBtn').addEventListener('click', () => {
        const select = document.getElementById('reportCaseSelect');
        if (select.value) {
          alert('Full PDF report generation would require a backend service. This demo shows the report preview in the UI.');
        } else {
          alert('Please select a case first.');
        }
      });
    }

    // ==================== PARTICLES ====================
    
    function createParticles() {
      const container = document.getElementById('particles');
      const particleCount = 20;

      for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 20 + 's';
        particle.style.animationDuration = (15 + Math.random() * 10) + 's';
        container.appendChild(particle);
      }
    }







    // ==================== BACKEND INTEGRATION ====================

async function sendLogToBackend(log) {
  try {
    console.log(log);
    await fetch("http://localhost:8080/api/logs", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(log)
    });
  } catch (error) {
    console.error("Error sending log to backend:", error);
  }
}

async function fetchLogsFromBackend() {
  try {
    const response = await fetch("http://localhost:8080/api/logs");
    if (!response.ok) return;

    const data = await response.json();

    attackLogs = data || [];
    incidentCases = []; // reset cases

    // 🔥 regenerate incident cases from backend logs
    attackLogs.forEach(log => {
      if (log.severity === 'critical' || log.confidence > 80) {
        createIncidentCase(log);
      }
    });

    updateDashboardStats();
    updateLiveFeed();
    updateLogsTable();
    updateCasesUI();

  } catch (error) {
    console.error("Error fetching logs:", error);
  }
}
    // ==================== LOGIN LOGIC =======================

    function setupLogin() {
      const loginScreen = document.getElementById('login-screen');
      const loginForm = document.getElementById('login-form');
      const loginError = document.getElementById('login-error');
      const sidebar = document.querySelector('.sidebar');
      const mainContent = document.querySelector('.main-content');
      const mobileToggle = document.getElementById('menuToggle');
      const logoutBtn = document.getElementById('logoutBtn');

      loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const user = document.getElementById('user').value;
        const pass = document.getElementById('pass').value;

        // Simple demo authentication
        if (user === 'admin' && pass === 'admin123') {
          loginScreen.classList.add('hidden');
          sidebar.style.display = 'block';
          mainContent.style.display = 'block';
          mobileToggle.style.display = 'flex'; // Show mobile toggle after login
          loginError.textContent = '';
        } else {
          loginError.textContent = 'Invalid Operator ID or Access Key';
          document.getElementById('pass').value = '';
        }
      });

      logoutBtn.addEventListener('click', () => {
        loginScreen.classList.remove('hidden');
        sidebar.style.display = 'none';
        mainContent.style.display = 'none';
        mobileToggle.style.display = 'none';
        document.getElementById('pass').value = '';
      });
    }

    // ==================== STARTUP ====================
    
    document.addEventListener('DOMContentLoaded', () => {
      createParticles();
      setupLogin();
      setupEventHandlers();

      fetchLogsFromBackend(); // fetch existing logs first
    });

