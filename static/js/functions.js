// API Functions
async function fetchStats() {
    try {
        // Build filter parameters
        const params = new URLSearchParams();
        if (elements.filters.country.value) params.append('country', elements.filters.country.value);
        if (elements.filters.isp.value) params.append('isp', elements.filters.isp.value);
        if (elements.filters.ip.value) params.append('ip', elements.filters.ip.value);
        if (elements.filters.protocol.value) params.append('protocol', elements.filters.protocol.value);
        if (elements.filters.port.value) params.append('port', elements.filters.port.value);
        
        const response = await fetch('/api/stats?' + params.toString());
        if (!response.ok) throw new Error('Network response was not ok');
        return await response.json();
    } catch (error) {
        console.error('Error fetching stats:', error);
        return null;
    }
}

async function fetchIpAlias(ip) {
    try {
        const response = await fetch(`/api/ip_alias/${ip}`);
        if (!response.ok) throw new Error('Network response was not ok');
        return await response.json();
    } catch (error) {
        console.error('Error fetching IP alias:', error);
        return null;
    }
}

async function saveIpAlias(ip, alias, notes) {
    try {
        const response = await fetch(`/api/ip_alias/${ip}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alias, notes })
        });
        if (!response.ok) throw new Error('Network response was not ok');
        return await response.json();
    } catch (error) {
        console.error('Error saving IP alias:', error);
        return null;
    }
}

async function fetchPortMapping(port) {
    try {
        const response = await fetch(`/api/port_mapping/${port}`);
        if (!response.ok) throw new Error('Network response was not ok');
        return await response.json();
    } catch (error) {
        console.error('Error fetching port mapping:', error);
        return null;
    }
}

async function savePortMapping(port, application, description, category) {
    try {
        const response = await fetch(`/api/port_mapping/${port}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ application, description, category })
        });
        if (!response.ok) throw new Error('Network response was not ok');
        return await response.json();
    } catch (error) {
        console.error('Error saving port mapping:', error);
        return null;
    }
}

async function deletePortMapping(port) {
    try {
        const response = await fetch(`/api/port_mapping/${port}`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Network response was not ok');
        return await response.json();
    } catch (error) {
        console.error('Error deleting port mapping:', error);
        return null;
    }
}

// Update Dashboard
async function updateDashboard() {
    const data = await fetchStats();
    if (!data) return;
    
    // Update statistics
    elements.totalPackets.textContent = data.total_packets;
    elements.tcpPackets.textContent = data.tcp_packets;
    elements.udpPackets.textContent = data.udp_packets;
    elements.otherPackets.textContent = data.other_packets;
    
    // Update size distribution chart
    updateSizeDistributionChart(data.size_distribution);
    
    // Update tables
    updatePacketsTable(data.recent_packets);
    updateFlowsTable(data.active_flows);
}

// IP Alias Modal Handlers
async function handleIpClick(ip) {
    const data = await fetchIpAlias(ip);
    if (!data) return;
    
    document.getElementById('ipAddress').value = ip;
    document.getElementById('ipAlias').value = data.alias || '';
    document.getElementById('ipNotes').value = data.notes || '';
    
    ipAliasModal.show();
}

document.getElementById('saveIpAlias').addEventListener('click', async function() {
    const ip = document.getElementById('ipAddress').value;
    const alias = document.getElementById('ipAlias').value;
    const notes = document.getElementById('ipNotes').value;
    
    const result = await saveIpAlias(ip, alias, notes);
    if (result && result.success) {
        ipAliasModal.hide();
        updateDashboard();
    }
});

// Port Mapping Modal Handlers
async function handlePortClick(port) {
    const data = await fetchPortMapping(port);
    if (!data) return;
    
    document.getElementById('portNumber').value = port;
    document.getElementById('portApplication').value = data.application || '';
    document.getElementById('portDescription').value = data.description || '';
    document.getElementById('portCategory').value = data.category || '';
    
    portMappingModal.show();
}

document.getElementById('savePortMapping').addEventListener('click', async function() {
    const port = document.getElementById('portNumber').value;
    const application = document.getElementById('portApplication').value;
    const description = document.getElementById('portDescription').value;
    const category = document.getElementById('portCategory').value;
    
    const result = await savePortMapping(port, application, description, category);
    if (result && result.success) {
        portMappingModal.hide();
        updateDashboard();
    }
}); 