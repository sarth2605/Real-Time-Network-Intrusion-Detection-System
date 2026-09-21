/**
 * ==============================================================================
 * Real-Time Network Intrusion Detection System (NIDS)
 * Alerts Management & Threat Archive Controller (static/js/alerts.js)
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
    const alertsTable = document.getElementById('alertsTable');
    const alertsTableBody = document.getElementById('alertsTableBody');
    const emptyAlertsRow = document.getElementById('emptyAlertsRow');
    const noMatchRow = document.getElementById('noMatchRow');

    // Filter Controls
    const filterSearch = document.getElementById('filterSearch');
    const filterSeverity = document.getElementById('filterSeverity');
    const filterType = document.getElementById('filterType');
    const btnResetFilters = document.getElementById('btnResetFilters');
    const filterResultBadge = document.getElementById('filterResultBadge');

    // Export Buttons
    const btnExportCSV = document.getElementById('btnExportCSV');
    const btnExportCSVTable = document.getElementById('btnExportCSVTable');

    // 5 Severity / Alert KPI Counters
    const kpiTotalAlerts = document.getElementById('kpiTotalAlerts');
    const kpiCardCrit = document.getElementById('kpiCardCrit');
    const kpiCardHigh = document.getElementById('kpiCardHigh');
    const kpiCardMed = document.getElementById('kpiCardMed');
    const kpiCardLow = document.getElementById('kpiCardLow');

    // Header Quick Summary Badges
    const headerSevCrit = document.getElementById('headerSevCrit');
    const headerSevHigh = document.getElementById('headerSevHigh');
    const headerSevMed = document.getElementById('headerSevMed');
    const headerSevLow = document.getElementById('headerSevLow');

    // Sidebar Indicators
    const sidebarAlertPill = document.getElementById('sidebarAlertPill');
    const mobileMenuToggle = document.getElementById('mobileMenuToggle');
    const socSidebar = document.getElementById('socSidebar');

    // Initial tally calculation and filter pass
    updateDynamicCounters();
    applyFilters();

    // --------------------------------------------------------------------------
    // 3. REAL-TIME WEBSOCKET EVENT LISTENERS
    // --------------------------------------------------------------------------

    socket.on('connect', () => {
        console.log('[NIDS Alerts] WebSocket connected to real-time incident feed.');
    });

    // When a newly detected intrusion alert arrives:
    socket.on('new_alert', (alert) => {
        console.warn('[NIDS Alerts] Incoming real-time security alert:', alert);

        // Remove placeholder empty state if present
        const emptyState = document.getElementById('emptyAlertsRow');
        if (emptyState) emptyState.remove();

        // Build new table row
        const row = document.createElement('tr');
        row.className = 'new-alert-row';

        const sevUpper = (alert.severity || 'HIGH').toUpperCase();
        const sevLower = sevUpper.toLowerCase();
        const attackName = alert.attack_type || 'Suspicious Activity';
        const srcIp = alert.source_ip || '0.0.0.0';
        const dstIp = alert.destination_ip || '-';
        const dstPort = alert.target_port ? `:${alert.target_port}` : '';
        const desc = alert.description || 'Intrusion pattern identified.';
        const ts = alert.timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19);
        const status = alert.status || 'Active';
        const alertId = alert.id ? `#${alert.id}` : '#LIVE';

        // Set filtering metadata attributes
        row.setAttribute('data-id', alert.id ? String(alert.id) : '');
        row.setAttribute('data-severity', sevUpper);
        row.setAttribute('data-type', attackName);
        row.setAttribute('data-src-ip', srcIp.toLowerCase());
        row.setAttribute('data-dst-ip', dstIp.toLowerCase());
        row.setAttribute('data-desc', desc.toLowerCase());

        row.innerHTML = `
            <td class="mono-ip">${alertId}</td>
            <td><strong class="attack-title">${attackName}</strong></td>
            <td class="mono-ip text-red">${srcIp}</td>
            <td class="mono-ip">${dstIp}${dstPort}</td>
            <td>
                <span class="badge-sev badge-sev-${sevLower}">${sevUpper}</span>
            </td>
            <td class="investigation-summary">${desc}</td>
            <td class="mono-ip">${ts}</td>
            <td><span class="status-chip-active">${status}</span></td>
        `;

        // Prepend so that the most recent alerts are always on top
        alertsTableBody.insertBefore(row, alertsTableBody.firstChild);

        // Re-apply active filters and update metric cards
        applyFilters();
        updateDynamicCounters();
    });

    // When global statistics are updated:
    socket.on('stats_update', (stats) => {
        if (!stats) return;

        if (stats.total_alerts !== undefined && kpiTotalAlerts) {
            kpiTotalAlerts.textContent = stats.total_alerts;
        }
        if (sidebarAlertPill && stats.total_alerts !== undefined) {
            sidebarAlertPill.textContent = `${stats.total_alerts} alerts`;
        }

        if (stats.severity_breakdown) {
            const sb = stats.severity_breakdown;
            if (kpiCardCrit) kpiCardCrit.textContent = sb.CRITICAL || 0;
            if (kpiCardHigh) kpiCardHigh.textContent = sb.HIGH || 0;
            if (kpiCardMed) kpiCardMed.textContent = sb.MEDIUM || 0;
            if (kpiCardLow) kpiCardLow.textContent = sb.LOW || 0;

            if (headerSevCrit) headerSevCrit.textContent = sb.CRITICAL || 0;
            if (headerSevHigh) headerSevHigh.textContent = sb.HIGH || 0;
            if (headerSevMed) headerSevMed.textContent = sb.MEDIUM || 0;
            if (headerSevLow) headerSevLow.textContent = sb.LOW || 0;
        }
    });

    // --------------------------------------------------------------------------
    // 4. MULTI-CRITERIA FILTERING & LIVE SEARCH LOGIC
    // --------------------------------------------------------------------------

    function applyFilters() {
        const query = filterSearch.value.trim().toLowerCase();
        const selectedSev = filterSeverity.value.toUpperCase();
        const selectedType = filterType.value;

        const allRows = alertsTableBody.querySelectorAll('tr');
        let totalRecords = 0;
        let visibleRecords = 0;

        allRows.forEach(row => {
            // Skip the static placeholder rows
            if (row.id === 'emptyAlertsRow' || row.id === 'noMatchRow') return;

            totalRecords++;

            const rowId = (row.getAttribute('data-id') || '').toLowerCase();
            const rowSev = (row.getAttribute('data-severity') || '').toUpperCase();
            const rowType = row.getAttribute('data-type') || '';
            const rowSrcIp = (row.getAttribute('data-src-ip') || '').toLowerCase();
            const rowDstIp = (row.getAttribute('data-dst-ip') || '').toLowerCase();
            const rowDesc = (row.getAttribute('data-desc') || '').toLowerCase();
            const fullText = row.textContent.toLowerCase();

            // Severity filter rule
            const matchesSeverity = (selectedSev === 'ALL' || rowSev === selectedSev);

            // Attack type filter rule
            const matchesType = (selectedType === 'ALL' || rowType === selectedType);

            // Search query filter rule (across IP, Attack Name, Description, and ID)
            const matchesSearch = !query || 
                rowSrcIp.includes(query) || 
                rowDstIp.includes(query) || 
                rowType.toLowerCase().includes(query) || 
                rowDesc.includes(query) || 
                rowId.includes(query) ||
                fullText.includes(query);

            if (matchesSeverity && matchesType && matchesSearch) {
                row.style.display = '';
                visibleRecords++;
            } else {
                row.style.display = 'none';
            }
        });

        // Update results counter badge
        if (filterResultBadge) {
            filterResultBadge.textContent = `Showing ${visibleRecords} of ${totalRecords} alerts`;
        }

        // Display "No matching records" row if search yields zero results
        if (noMatchRow) {
            if (visibleRecords === 0 && totalRecords > 0) {
                noMatchRow.style.display = '';
            } else {
                noMatchRow.style.display = 'none';
            }
        }
    }

    // Attach real-time input event listeners for instantaneous filtering
    filterSearch.addEventListener('input', applyFilters);
    filterSeverity.addEventListener('change', applyFilters);
    filterType.addEventListener('change', applyFilters);

    // Reset button to restore full view
    btnResetFilters.addEventListener('click', () => {
        filterSearch.value = '';
        filterSeverity.value = 'ALL';
        filterType.value = 'ALL';
        applyFilters();
    });

    // --------------------------------------------------------------------------
    // 5. METRIC CARDS SYNCHRONIZATION
    // --------------------------------------------------------------------------

    function updateDynamicCounters() {
        let crit = 0, high = 0, med = 0, low = 0;
        let total = 0;

        const allRows = alertsTableBody.querySelectorAll('tr');
        allRows.forEach(row => {
            if (row.id === 'emptyAlertsRow' || row.id === 'noMatchRow') return;
            total++;
            const sev = (row.getAttribute('data-severity') || '').toUpperCase();
            if (sev === 'CRITICAL') crit++;
            else if (sev === 'HIGH') high++;
            else if (sev === 'MEDIUM') med++;
            else if (sev === 'LOW') low++;
        });

        if (kpiTotalAlerts) kpiTotalAlerts.textContent = total;
        if (kpiCardCrit) kpiCardCrit.textContent = crit;
        if (kpiCardHigh) kpiCardHigh.textContent = high;
        if (kpiCardMed) kpiCardMed.textContent = med;
        if (kpiCardLow) kpiCardLow.textContent = low;

        if (headerSevCrit) headerSevCrit.textContent = crit;
        if (headerSevHigh) headerSevHigh.textContent = high;
        if (headerSevMed) headerSevMed.textContent = med;
        if (headerSevLow) headerSevLow.textContent = low;

        if (sidebarAlertPill) sidebarAlertPill.textContent = `${total} alerts`;
    }

    // --------------------------------------------------------------------------
    // 6. CSV AUDIT LOG EXPORT
    // --------------------------------------------------------------------------

    function exportTableToCSV() {
        const allRows = alertsTableBody.querySelectorAll('tr');
        const exportRows = [];

        allRows.forEach(row => {
            if (row.id === 'emptyAlertsRow' || row.id === 'noMatchRow') return;
            // Only export currently visible (filtered) rows
            if (row.style.display !== 'none') {
                const cols = row.querySelectorAll('td');
                if (cols.length >= 8) {
                    exportRows.push([
                        cols[0].textContent.trim(),                         // Alert ID
                        `"${cols[1].textContent.trim().replace(/"/g, '""')}"`, // Attack Type
                        cols[2].textContent.trim(),                         // Source IP
                        cols[3].textContent.trim(),                         // Destination IP
                        cols[4].textContent.trim(),                         // Severity
                        `"${cols[5].textContent.trim().replace(/"/g, '""')}"`, // Description
                        cols[6].textContent.trim(),                         // Timestamp
                        cols[7].textContent.trim()                          // Status
                    ]);
                }
            }
        });

        if (exportRows.length === 0) {
            alert('No security alert records to export with the current filter settings.');
            return;
        }

        const headers = ['Alert ID', 'Attack Type', 'Source IP', 'Destination IP', 'Severity', 'Description', 'Timestamp', 'Status'];
        const csvContent = [headers.join(','), ...exportRows.map(r => r.join(','))].join('\r\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = `nids_security_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(downloadUrl);
    }

    if (btnExportCSV) btnExportCSV.addEventListener('click', exportTableToCSV);
    if (btnExportCSVTable) btnExportCSVTable.addEventListener('click', exportTableToCSV);

    // --------------------------------------------------------------------------
    // 7. RESPONSIVE MOBILE SIDEBAR TOGGLE
    // --------------------------------------------------------------------------
    if (mobileMenuToggle && socSidebar) {
        mobileMenuToggle.addEventListener('click', () => {
            socSidebar.classList.toggle('open');
        });
    }
});

