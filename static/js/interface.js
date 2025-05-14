// Initialize timezone handling
let currentTimezone = moment.tz.guess();

// Initialize charts
let sizeDistributionChart = null;

// Initialize modals
const ipAliasModal = new bootstrap.Modal(document.getElementById('ipAliasModal'));
const portMappingModal = new bootstrap.Modal(document.getElementById('portMappingModal'));

// DOM Elements
const elements = {
    timezoneSelect: document.getElementById('timezoneSelect'),
    refreshButton: document.getElementById('refreshButton'),
    totalPackets: document.getElementById('totalPackets'),
    tcpPackets: document.getElementById('tcpPackets'),
    udpPackets: document.getElementById('udpPackets'),
    otherPackets: document.getElementById('otherPackets'),
    packetsTable: document.getElementById('packetsTable'),
    flowsTable: document.getElementById('flowsTable'),
    sizeDistributionChart: document.getElementById('sizeDistributionChart'),
    filters: {
        country: document.getElementById('countryFilter'),
        isp: document.getElementById('ispFilter'),
        ip: document.getElementById('ipFilter'),
        protocol: document.getElementById('protocolFilter'),
        port: document.getElementById('portFilter')
    }
};

// Initialize timezone select
function populateTimezones() {
    const timezones = moment.tz.names();
    const currentOffset = moment.tz(currentTimezone).format('Z');
    
    // Group timezones by offset
    const tzGroups = {};
    timezones.forEach(tz => {
        const offset = moment.tz(tz).format('Z');
        if (!tzGroups[offset]) {
            tzGroups[offset] = [];
        }
        tzGroups[offset].push(tz);
    });
    
    // Sort by offset
    const sortedOffsets = Object.keys(tzGroups).sort((a, b) => {
        return moment.duration(a).asMinutes() - moment.duration(b).asMinutes();
    });
    
    // Create option groups by offset
    elements.timezoneSelect.innerHTML = '';
    sortedOffsets.forEach(offset => {
        const optgroup = document.createElement('optgroup');
        optgroup.label = `UTC${offset}`;
        
        tzGroups[offset].sort().forEach(tz => {
            const option = document.createElement('option');
            option.value = tz;
            option.text = tz.replace(/_/g, ' ');
            option.selected = tz === currentTimezone;
            optgroup.appendChild(option);
        });
        
        elements.timezoneSelect.appendChild(optgroup);
    });
}

// Initialize size distribution chart
function initializeSizeDistributionChart() {
    const ctx = elements.sizeDistributionChart.getContext('2d');
    sizeDistributionChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['0-64', '65-128', '129-256', '257-512', '513-1024', '1024+'],
            datasets: [{
                label: 'Packet Size Distribution',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: 'rgba(54, 162, 235, 0.5)',
                borderColor: 'rgba(54, 162, 235, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Update size distribution chart
function updateSizeDistributionChart(data) {
    if (sizeDistributionChart) {
        sizeDistributionChart.data.datasets[0].data = data;
        sizeDistributionChart.update();
    }
}

// Format timestamps according to selected timezone
function formatTimestamp(timestamp) {
    return moment.tz(timestamp, currentTimezone).format('YYYY-MM-DD HH:mm:ss.SSS z');
}

// Format bytes to human readable format
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    else if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    else return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

// Format bytes per second
function formatBytesPerSec(bytesPerSec) {
    return formatBytes(bytesPerSec) + '/s';
}

// Format duration in seconds to human readable format
function formatDuration(seconds) {
    if (seconds < 60) return seconds + 's';
    const minutes = Math.floor(seconds / 60);
    seconds = seconds % 60;
    if (minutes < 60) return `${minutes}m ${seconds}s`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ${minutes % 60}m ${seconds}s`;
}

// Update packets table
function updatePacketsTable(packets) {
    const tbody = elements.packetsTable.querySelector('tbody');
    tbody.innerHTML = '';
    
    packets.forEach(packet => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formatTimestamp(packet.timestamp)}</td>
            <td class="ip-address" onclick="handleIpClick('${packet.src_ip}')">${packet.src_ip}${packet.src_alias ? ' (' + packet.src_alias + ')' : ''}</td>
            <td class="ip-address" onclick="handleIpClick('${packet.dst_ip}')">${packet.dst_ip}${packet.dst_alias ? ' (' + packet.dst_alias + ')' : ''}</td>
            <td>${packet.protocol}</td>
            <td class="bytes-cell">${formatBytes(packet.length)}</td>
            <td class="port-number" onclick="handlePortClick(${packet.src_port})">${packet.src_port}${packet.src_app ? ' (' + packet.src_app + ')' : ''}</td>
            <td class="port-number" onclick="handlePortClick(${packet.dst_port})">${packet.dst_port}${packet.dst_app ? ' (' + packet.dst_app + ')' : ''}</td>
            <td>${packet.country || 'Unknown'}</td>
            <td>${packet.isp || 'Unknown'}</td>
        `;
        tbody.appendChild(row);
    });
}

// Update flows table
function updateFlowsTable(flows) {
    const tbody = elements.flowsTable.querySelector('tbody');
    tbody.innerHTML = '';
    
    flows.forEach(flow => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td class="ip-address" onclick="handleIpClick('${flow.src_ip}')">${flow.src_ip}${flow.src_alias ? ' (' + flow.src_alias + ')' : ''}</td>
            <td class="ip-address" onclick="handleIpClick('${flow.dst_ip}')">${flow.dst_ip}${flow.dst_alias ? ' (' + flow.dst_alias + ')' : ''}</td>
            <td class="bytes-cell">${formatBytes(flow.bytes)}</td>
            <td>${flow.packets}</td>
            <td class="duration-cell">${formatDuration(flow.duration)}</td>
            <td class="bytes-cell">${formatBytesPerSec(flow.bytes_per_sec)}</td>
        `;
        tbody.appendChild(row);
    });
}

// Event Listeners
elements.timezoneSelect.addEventListener('change', function() {
    currentTimezone = this.value;
    localStorage.setItem('selectedTimezone', currentTimezone);
    updateDashboard();
});

elements.refreshButton.addEventListener('click', updateDashboard);

// Filter change handlers
Object.values(elements.filters).forEach(filter => {
    filter.addEventListener('change', updateDashboard);
    filter.addEventListener('keyup', updateDashboard);
});

// Initialize interface
function initializeInterface() {
    populateTimezones();
    initializeSizeDistributionChart();
    
    // Restore timezone from localStorage
    const savedTimezone = localStorage.getItem('selectedTimezone');
    if (savedTimezone) {
        currentTimezone = savedTimezone;
        elements.timezoneSelect.value = currentTimezone;
    }
    
    // Start periodic updates
    updateDashboard();
    setInterval(updateDashboard, 2000);
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initializeInterface); 