/**
 * ==============================================================================
 * Real-Time Network Intrusion Detection System (NIDS)
 * SOC Dashboard Controller (Socket.IO + 3 Dynamic Chart.js Charts)
 * ==============================================================================
 */

document.addEventListener('DOMContentLoaded', () => {
    // --------------------------------------------------------------------------
    // 1. WEBSOCKET CLIENT INITIALIZATION
    // --------------------------------------------------------------------------
    const socket = io();

    // --------------------------------------------------------------------------
    // 2. DOM ELEMENT REFERENCES
    // --------------------------------------------------------------------------
    // 5 Core KPI Counters
    const kpiTotalPackets = document.getElementById('kpiTotalPackets');
    const kpiNormalTraffic = document.getElementById('kpiNormalTraffic');
    const kpiSuspicious = document.getElementById('kpiSuspicious');
    const kpiBruteForce = document.getElementById('kpiBruteForce');
    const kpiPortScan = document.getElementById('kpiPortScan');

    // Quick Severity Counters (Header Bar)
    const kpiSevCrit = document.getElementById('kpiSevCrit');
    const kpiSevHigh = document.getElementById('kpiSevHigh');
    const kpiSevMed = document.getElementById('kpiSevMed');
    const kpiSevLow = document.getElementById('kpiSevLow');

    // Chart Badges & Indicators
    const chartLiveRate = document.getElementById('chartLiveRate');
    const totalAttacksBadge = document.getElementById('totalAttacksBadge');
    const totalSeverityBadge = document.getElementById('totalSeverityBadge');

    // Sidebar & Status Elements
    const engineStatusDot = document.getElementById('engineStatusDot');
    const engineStatusText = document.getElementById('engineStatusText');
    const sidebarFps = document.getElementById('sidebarFps');
    const sidebarAlertCount = document.getElementById('sidebarAlertCount');

    // Tables
    const recentAlertsTableBody = document.getElementById('recentAlertsTableBody');
    const livePacketTableBody = document.getElementById('livePacketTableBody');
    const btnPauseStream = document.getElementById('btnPauseStream');
    const streamStatusBadge = document.getElementById('streamStatusBadge');

    // Controls
    const btnLiveMode = document.getElementById('btnLiveMode');
    const btnSimMode = document.getElementById('btnSimMode');
    const btnStopCapture = document.getElementById('btnStopCapture');
    const btnClearData = document.getElementById('btnClearData');
    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const socSidebar = document.getElementById('socSidebar');

    // Internal State
    let isStreamPaused = false;
    let packetsCounterThisSecond = 0;
    const MAX_PACKET_ROWS = 30;
    const MAX_ALERT_ROWS = 20;

    // Severity Statistics Tally
    const severityStats = {
        LOW: 0,
        MEDIUM: 0,
        HIGH: 0,
        CRITICAL: 0
    };

    // Attack Classifications Tally
    const attackStats = {
        'Port Scan': 0,
        'Brute Force': 0,
        'Suspicious': 0
    };

    // --------------------------------------------------------------------------
    // 3. CHART 1: NETWORK TRAFFIC VELOCITY (LINE CHART - ACTIVITY OVER TIME)
    // --------------------------------------------------------------------------
    const ctxTrend = document.getElementById('trafficTrendChart').getContext('2d');
    
    // Soft neon-cyan gradient fill
    const gradientTrend = ctxTrend.createLinearGradient(0, 0, 0, 240);
    gradientTrend.addColorStop(0, 'rgba(0, 240, 255, 0.30)');
    gradientTrend.addColorStop(1, 'rgba(0, 240, 255, 0.00)');

    const trendLabels = Array(15).fill('').map((_, i) => `${15 - i}s`);
    const trendData = Array(15).fill(0);

    const trafficTrendChart = new Chart(ctxTrend, {
        type: 'line',
        data: {
            labels: trendLabels,
            datasets: [{
                label: 'Packets / Sec',
                data: trendData,
                borderColor: '#00f0ff',
                backgroundColor: gradientTrend,
                borderWidth: 2.2,
                tension: 0.35,
                fill: true,
                pointRadius: 2,
                pointHoverRadius: 6,
                pointBackgroundColor: '#00f0ff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: 8,
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 2 }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    titleFont: { family: 'JetBrains Mono' },
                    bodyFont: { family: 'JetBrains Mono' },
                    borderColor: 'rgba(0, 240, 255, 0.3)',
                    borderWidth: 1
                }
            }
        }
    });

    // --------------------------------------------------------------------------
    // 4. CHART 2: ATTACK DISTRIBUTION (BAR / DOUGHNUT CHART - DETECTED ATTACKS)
    // --------------------------------------------------------------------------
    const ctxAttack = document.getElementById('attackDistributionChart').getContext('2d');
    const attackDistributionChart = new Chart(ctxAttack, {
        type: 'bar',
        data: {
            labels: ['Port Scan', 'Brute Force', 'Suspicious'],
            datasets: [{
                label: 'Detections',
                data: [0, 0, 0],
                backgroundColor: [
                    '#a855f7', // Port Scan (Electric Purple)
                    '#ef4444', // Brute Force (Crimson Red)
                    '#f59e0b'  // Suspicious Activity (Amber)
                ],
                borderRadius: 6,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { display: false },
                    ticks: {
                        color: '#94a3b8',
                        font: { family: 'Plus Jakarta Sans', size: 11, weight: '600' }
                    }
                },
                y: {
                    beginAtZero: true,
                    suggestedMax: 5,
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: {
                        color: '#64748b',
                        font: { family: 'JetBrains Mono', size: 10 },
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1
                }
            }
        }
    });

    // --------------------------------------------------------------------------
    // 5. CHART 3: SEVERITY DISTRIBUTION (DOUGHNUT CHART - LOW TO CRITICAL)
    // --------------------------------------------------------------------------
    const ctxSeverity = document.getElementById('severityDistributionChart').getContext('2d');
    const severityDistributionChart = new Chart(ctxSeverity, {
        type: 'doughnut',
        data: {
            labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#38bdf8', // LOW (Cyan / Sky)
                    '#a855f7', // MEDIUM (Electric Purple)
                    '#f59e0b', // HIGH (Amber / Orange)
                    '#ef4444'  // CRITICAL (Crimson Red)
                ],
                borderColor: '#0f172a',
                borderWidth: 2,
                hoverOffset: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'Plus Jakarta Sans', size: 10, weight: '600' },
                        padding: 10,
                        boxWidth: 10
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15, 23, 42, 0.95)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1
                }
            }
        }
    });

    // --------------------------------------------------------------------------
    // 6. 1-SECOND VELOCITY INTERVAL TICKER (TRAFFIC OVER TIME SLIDING WINDOW)
    // --------------------------------------------------------------------------
    setInterval(() => {
        const pps = packetsCounterThisSecond;
        packetsCounterThisSecond = 0;

        // Update real-time velocity labels
        sidebarFps.textContent = `${pps} pkt/s`;
        chartLiveRate.textContent = `${pps} pkt/s`;

        // Slide the 15-second time window for Chart 1
        trendData.shift();
        trendData.push(pps);
        trafficTrendChart.update();
    }, 1000);

    // --------------------------------------------------------------------------
    // 7. REAL-TIME WEBSOCKET EVENT LISTENERS
    // --------------------------------------------------------------------------

    socket.on('connect', () => {
        console.log('[NIDS] WebSocket connection established with SOC backend.');
        // Request immediate stats synchronization upon connecting
        socket.emit('request_stats');
    });

    socket.on('disconnect', () => {
        console.log('[NIDS] WebSocket disconnected from backend. Attempting reconnection...');
    });

    // Event: Live network packet frame received
    socket.on('live_packet', (packet) => {
        packetsCounterThisSecond++;

        // 1. Instantly update total packet count
        if (kpiTotalPackets) {
            const currentTotal = parseInt(kpiTotalPackets.textContent.replace(/,/g, '') || '0', 10);
            kpiTotalPackets.textContent = (currentTotal + 1).toLocaleString();
        }

        // 2. Instantly update normal traffic counter if non-malicious
        if ((packet.status === 'Normal' || !packet.status) && kpiNormalTraffic) {
            const currentNormal = parseInt(kpiNormalTraffic.textContent.replace(/,/g, '') || '0', 10);
            kpiNormalTraffic.textContent = (currentNormal + 1).toLocaleString();
        }

        // 3. Render to live stream table if feed is not paused
        if (!isStreamPaused) {
            prependPacketRow(packet);
        }
    });

    // Helper: Trigger visual alert flash animation on affected metric card
    function flashCard(element) {
        if (!element) return;
        const card = element.closest('.cyber-card');
        if (card) {
            card.classList.remove('card-alert-flash');
            void card.offsetWidth; // Force CSS reflow
            card.classList.add('card-alert-flash');
        }
    }

    // Event: Confirmed intrusion alert generated
    socket.on('new_alert', (alert) => {
        console.warn('[NIDS INTRUSION ALERT]', alert);

        // 1. Update Total Alerts Counter (Sidebar)
        if (sidebarAlertCount) {
            const currentAlerts = parseInt(sidebarAlertCount.textContent.replace(/,/g, '') || '0', 10);
            sidebarAlertCount.textContent = (currentAlerts + 1);
        }

        // 2. Update Attack Classification Statistics & Metric Cards
        const attackName = alert.attack_type || 'Suspicious Activity';
        if (attackName === 'Port Scan') {
            attackStats['Port Scan']++;
            if (kpiPortScan) {
                const cur = parseInt(kpiPortScan.textContent.replace(/,/g, '') || '0', 10);
                kpiPortScan.textContent = cur + 1;
                flashCard(kpiPortScan);
            }
        } else if (attackName === 'Brute Force') {
            attackStats['Brute Force']++;
            if (kpiBruteForce) {
                const cur = parseInt(kpiBruteForce.textContent.replace(/,/g, '') || '0', 10);
                kpiBruteForce.textContent = cur + 1;
                flashCard(kpiBruteForce);
            }
        } else {
            attackStats['Suspicious']++;
            if (kpiSuspicious) {
                const cur = parseInt(kpiSuspicious.textContent.replace(/,/g, '') || '0', 10);
                kpiSuspicious.textContent = cur + 1;
                flashCard(kpiSuspicious);
            }
        }
        updateAttackChart();

        // 3. Update Severity Statistics & Doughnut Chart
        const sev = (alert.severity || 'HIGH').toUpperCase();
        if (severityStats[sev] !== undefined) {
            severityStats[sev]++;
            updateSeverityViews();
        }

        // 4. Prepend to Recent Security Alerts Table with Flash Animation
        prependAlertRow(alert, true);
    });

    // Event: System aggregate metrics update
    socket.on('stats_update', (stats) => {
        if (!stats) return;

        // Synchronize all 5 KPI counters
        if (stats.total_packets !== undefined && kpiTotalPackets) {
            kpiTotalPackets.textContent = Number(stats.total_packets).toLocaleString();
        }
        if (stats.normal_traffic !== undefined && kpiNormalTraffic) {
            kpiNormalTraffic.textContent = Number(stats.normal_traffic).toLocaleString();
        }
        if (stats.suspicious_count !== undefined && kpiSuspicious) {
            kpiSuspicious.textContent = stats.suspicious_count;
        }
        if (stats.brute_force_count !== undefined && kpiBruteForce) {
            kpiBruteForce.textContent = stats.brute_force_count;
        }
        if (stats.port_scan_count !== undefined && kpiPortScan) {
            kpiPortScan.textContent = stats.port_scan_count;
        }
        if (stats.total_alerts !== undefined && sidebarAlertCount) {
            sidebarAlertCount.textContent = stats.total_alerts;
        }

        // Synchronize attack chart data from backend stats
        if (stats.attack_breakdown) {
            if (stats.attack_breakdown['Port Scan'] !== undefined) attackStats['Port Scan'] = stats.attack_breakdown['Port Scan'];
            if (stats.attack_breakdown['Brute Force'] !== undefined) attackStats['Brute Force'] = stats.attack_breakdown['Brute Force'];
            if (stats.attack_breakdown['Suspicious Activity'] !== undefined) attackStats['Suspicious'] = stats.attack_breakdown['Suspicious Activity'];
        } else {
            if (stats.port_scan_count !== undefined) attackStats['Port Scan'] = stats.port_scan_count;
            if (stats.brute_force_count !== undefined) attackStats['Brute Force'] = stats.brute_force_count;
            if (stats.suspicious_count !== undefined) attackStats['Suspicious'] = stats.suspicious_count;
        }
        updateAttackChart();

        // Synchronize severity breakdown for doughnut chart and quick bar
        if (stats.severity_breakdown) {
            severityStats.LOW = stats.severity_breakdown.LOW || 0;
            severityStats.MEDIUM = stats.severity_breakdown.MEDIUM || 0;
            severityStats.HIGH = stats.severity_breakdown.HIGH || 0;
            severityStats.CRITICAL = stats.severity_breakdown.CRITICAL || 0;
            updateSeverityViews();
        }
    });

    // --------------------------------------------------------------------------
    // 8. DOM & CHART RENDERING SYNCHRONIZATION HELPERS
    // --------------------------------------------------------------------------

    function updateAttackChart() {
        const portScanVal = attackStats['Port Scan'];
        const bruteForceVal = attackStats['Brute Force'];
        const suspiciousVal = attackStats['Suspicious'];
        const total = portScanVal + bruteForceVal + suspiciousVal;

        attackDistributionChart.data.datasets[0].data = [
            portScanVal,
            bruteForceVal,
            suspiciousVal
        ];
        attackDistributionChart.update();

        if (totalAttacksBadge) {
            totalAttacksBadge.textContent = `${total} threats`;
        }
    }

    function updateSeverityViews() {
        const low = severityStats.LOW;
        const med = severityStats.MEDIUM;
        const high = severityStats.HIGH;
        const crit = severityStats.CRITICAL;
        const total = low + med + high + crit;

        // Update Chart 3 dataset
        severityDistributionChart.data.datasets[0].data = [low, med, high, crit];
        severityDistributionChart.update();

        // Update badge above chart
        if (totalSeverityBadge) {
            totalSeverityBadge.textContent = `${total} alerts`;
        }

        // Update top header quick severity bar
        if (kpiSevCrit) kpiSevCrit.textContent = crit;
        if (kpiSevHigh) kpiSevHigh.textContent = high;
        if (kpiSevMed) kpiSevMed.textContent = med;
        if (kpiSevLow) kpiSevLow.textContent = low;
    }

    function prependPacketRow(pkt) {
        const row = document.createElement('tr');
        const isThreat = pkt.status && pkt.status !== 'Normal';
        const statusClass = isThreat ? 'text-red' : 'text-green';

        row.innerHTML = `
            <td class="mono-ip">${pkt.timestamp.split(' ')[1] || pkt.timestamp}</td>
            <td class="mono-ip">${pkt.source_ip || pkt.src_ip}</td>
            <td class="mono-ip">${pkt.destination_ip || pkt.dst_ip}</td>
            <td><span class="protocol-tag">${pkt.protocol || 'TCP'}</span></td>
            <td class="mono-ip">${pkt.destination_port || pkt.dst_port || '-'}</td>
            <td class="mono-ip">${pkt.packet_size} B</td>
            <td><strong class="${statusClass}">${pkt.status || 'Normal'}</strong></td>
        `;

        livePacketTableBody.insertBefore(row, livePacketTableBody.firstChild);

        // Cap rows to keep DOM memory light and scrolling smooth
        if (livePacketTableBody.children.length > MAX_PACKET_ROWS) {
            livePacketTableBody.removeChild(livePacketTableBody.lastChild);
        }
    }

    function prependAlertRow(alert, isLive = false) {
        const emptyState = document.getElementById('emptyAlertsRow');
        if (emptyState) emptyState.remove();

        const row = document.createElement('tr');
        if (isLive) {
            row.className = 'new-alert-row';
        }

        const sevLower = (alert.severity || 'high').toLowerCase();
        const sevClass = `badge-sev-${sevLower}`;

        row.innerHTML = `
            <td class="mono-ip">#${alert.id || 'LIVE'}</td>
            <td class="mono-ip">${alert.timestamp}</td>
            <td><strong class="attack-title">${alert.attack_type}</strong></td>
            <td class="mono-ip">${alert.source_ip}</td>
            <td class="mono-ip">${alert.destination_ip || '-'}:${alert.target_port || '-'}</td>
            <td>
                <span class="badge-sev ${sevClass}">${alert.severity}</span>
            </td>
            <td class="investigation-summary">${alert.description}</td>
            <td><span class="status-chip-active">${alert.status || 'Active'}</span></td>
        `;

        recentAlertsTableBody.insertBefore(row, recentAlertsTableBody.firstChild);

        if (recentAlertsTableBody.children.length > MAX_ALERT_ROWS) {
            recentAlertsTableBody.removeChild(recentAlertsTableBody.lastChild);
        }
    }

    // --------------------------------------------------------------------------
    // 9. CONTROLS & INTERACTIVE BUTTONS
    // --------------------------------------------------------------------------

    // Start Live Capture
    btnLiveMode.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: 'live' })
            });
            const data = await res.json();
            updateEnginePill(true, 'Live Capture (Scapy)');
        } catch (e) {
            alert('Unable to initiate live packet capture: ' + e);
        }
    });

    // Run Demo Simulator
    btnSimMode.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: 'sim' })
            });
            const data = await res.json();
            updateEnginePill(true, 'Active (Demo Mode)');
        } catch (e) {
            alert('Unable to start simulation: ' + e);
        }
    });

    // Safe Demonstration Scenario Triggers
    const simButtons = document.querySelectorAll('.btn-sim, .btn-sim-scenario');
    simButtons.forEach(btn => {
        btn.addEventListener('click', async () => {
            const scenario = btn.getAttribute('data-scenario') || 'normal';
            btn.style.opacity = '0.6';
            btn.style.pointerEvents = 'none';

            try {
                const res = await fetch('/api/simulate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ scenario: scenario })
                });
                const result = await res.json();
                console.log(`[Simulation] Triggered scenario '${scenario}':`, result);
            } catch (err) {
                console.error('[Simulation] Failed to trigger scenario:', err);
            } finally {
                setTimeout(() => {
                    btn.style.opacity = '1';
                    btn.style.pointerEvents = 'auto';
                }, 800);
            }
        });
    });

    // Stop Capture
    btnStopCapture.addEventListener('click', async () => {
        try {
            await fetch('/api/capture/stop', { method: 'POST' });
            updateEnginePill(false, 'Engine Stopped');
        } catch (e) {
            alert('Unable to stop capture: ' + e);
        }
    });

    // Reset Data Session
    btnClearData.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to clear all active session logs and alerts?')) return;
        try {
            await fetch('/api/alerts/clear', { method: 'POST' });
            location.reload();
        } catch (e) {
            alert('Failed to clear data: ' + e);
        }
    });

    // Pause / Resume Stream Table
    btnPauseStream.addEventListener('click', () => {
        isStreamPaused = !isStreamPaused;
        btnPauseStream.textContent = isStreamPaused ? 'Resume Feed' : 'Pause Feed';
        btnPauseStream.style.color = isStreamPaused ? '#00f0ff' : '#94a3b8';
        streamStatusBadge.textContent = isStreamPaused ? 'PAUSED' : 'STREAMING';
        streamStatusBadge.style.background = isStreamPaused ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.15)';
        streamStatusBadge.style.color = isStreamPaused ? '#fbbf24' : '#34d399';
    });

    // Mobile Sidebar Toggle
    if (mobileMenuToggle) {
        mobileMenuToggle.addEventListener('click', () => {
            socSidebar.classList.toggle('open');
        });
    }

    function updateEnginePill(isActive, labelText) {
        engineStatusText.textContent = labelText;
        engineStatusDot.className = isActive ? 'status-dot pulse-green' : 'status-dot pulse-red';
    }

    // --------------------------------------------------------------------------
    // 10. INITIAL DATA HYDRATION (FROM FLASK REST ENDPOINTS)
    // --------------------------------------------------------------------------
    // Fetch initial stats from /api/stats to hydrate all 3 charts on page load
    fetch('/api/stats')
        .then(r => r.json())
        .then(stats => {
            if (!stats) return;
            if (stats.port_scan_count !== undefined) attackStats['Port Scan'] = stats.port_scan_count;
            if (stats.brute_force_count !== undefined) attackStats['Brute Force'] = stats.brute_force_count;
            if (stats.suspicious_count !== undefined) attackStats['Suspicious'] = stats.suspicious_count;
            updateAttackChart();

            if (stats.severity_breakdown) {
                severityStats.LOW = stats.severity_breakdown.LOW || 0;
                severityStats.MEDIUM = stats.severity_breakdown.MEDIUM || 0;
                severityStats.HIGH = stats.severity_breakdown.HIGH || 0;
                severityStats.CRITICAL = stats.severity_breakdown.CRITICAL || 0;
                updateSeverityViews();
            }
        })
        .catch(err => console.log('Stats hydration:', err));

    // Fetch initial recent alerts from /api/alerts to hydrate the alerts table
    fetch('/api/alerts?limit=10')
        .then(r => r.json())
        .then(alerts => {
            alerts.forEach(a => {
                prependAlertRow(a);
            });
        })
        .catch(() => {});

    // Fetch initial recent packets from /api/traffic to hydrate the packet sniffer table
    fetch('/api/traffic?limit=15')
        .then(r => r.json())
        .then(packets => {
            packets.forEach(p => {
                prependPacketRow(p);
            });
        })
        .catch(() => {});
});
