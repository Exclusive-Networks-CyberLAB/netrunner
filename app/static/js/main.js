/**
 * NetRunner OS — Main Application JavaScript
 * Handles: Tab switching, PCAP viewer, traffic flow, rewriter/replay, generator, profiles.
 */

document.addEventListener('DOMContentLoaded', () => {

    // ═══════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════

    let analysisData = null;   // Stored result from analyze_pcap
    let statusEventSource = null;

    // ═══════════════════════════════════════════════════════════════════
    // SIDEBAR TOGGLE
    // ═══════════════════════════════════════════════════════════════════

    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebarToggle');

    // Restore collapse state
    if (localStorage.getItem('sidebar-collapsed') === 'true') {
        sidebar.classList.add('collapsed');
    }

    sidebarToggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('collapsed'));
    });

    // ═══════════════════════════════════════════════════════════════════
    // TAB / PANE NAVIGATION
    // ═══════════════════════════════════════════════════════════════════

    const tabs = document.querySelectorAll('.nav-item');
    const panes = document.querySelectorAll('.tab-pane');

    function switchTab(tabId) {
        tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
        panes.forEach(p => p.classList.toggle('active', p.id === `pane-${tabId}`));
    }

    tabs.forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));

    // Nav links
    const rewriterNavLink = document.getElementById('rewriter-nav-to-viewer');
    if (rewriterNavLink) rewriterNavLink.addEventListener('click', () => switchTab('viewer'));

    // ═══════════════════════════════════════════════════════════════════
    // VIEW MODE SWITCHING (within Viewer tab)
    // ═══════════════════════════════════════════════════════════════════

    const viewBtns = document.querySelectorAll('.view-mode-btn');
    const viewPanels = document.querySelectorAll('.view-panel');

    function switchView(viewId) {
        viewBtns.forEach(b => b.classList.toggle('active', b.dataset.view === viewId));
        viewPanels.forEach(p => p.classList.toggle('hidden', p.id !== `view-${viewId}`));
    }

    viewBtns.forEach(b => b.addEventListener('click', () => switchView(b.dataset.view)));

    // ═══════════════════════════════════════════════════════════════════
    // PCAP UPLOAD & ANALYSIS
    // ═══════════════════════════════════════════════════════════════════

    const pcapFile = document.getElementById('pcapFile');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const analysisStatus = document.getElementById('analysisStatus');
    const viewerControls = document.getElementById('viewerControls');
    const packetCount = document.getElementById('packetCount');

    pcapFile.addEventListener('change', () => {
        analyzeBtn.disabled = !pcapFile.files.length;
    });

    analyzeBtn.addEventListener('click', async () => {
        if (!pcapFile.files.length) return;

        analysisStatus.classList.remove('hidden');
        analysisStatus.textContent = '[ Analyzing PCAP... ]';
        analyzeBtn.disabled = true;

        const formData = new FormData();
        formData.append('pcapFile', pcapFile.files[0]);

        try {
            const resp = await fetch('/analyze_pcap', { method: 'POST', body: formData });
            const data = await resp.json();

            if (data.error) {
                analysisStatus.textContent = `Error: ${data.error}`;
                analyzeBtn.disabled = false;
                return;
            }

            analysisData = data;
            analysisStatus.classList.add('hidden');
            viewerControls.classList.remove('hidden');
            packetCount.textContent = `${data.total_packets} packets | ${data.hosts.length} hosts | ${data.conversations.length} conversations`;

            renderPackets(data.packets);
            renderEndpoints(data.endpoints);
            renderConversations(data.conversations);
            renderFlowDiagram(data.conversations, data.endpoints);
            populateRewriterHosts(data.hosts);

            switchView('packets');

            // Enable rewriter tab
            document.getElementById('rewriterNoFile').classList.add('hidden');
            document.getElementById('rewriterContent').classList.remove('hidden');

        } catch (err) {
            analysisStatus.textContent = `Error: ${err.message}`;
        }
        analyzeBtn.disabled = false;
    });

    // ═══════════════════════════════════════════════════════════════════
    // PACKET TABLE
    // ═══════════════════════════════════════════════════════════════════

    const packetBody = document.getElementById('packetBody');
    const packetDetails = document.getElementById('packetDetails');

    function protoClass(proto) {
        const p = proto.toLowerCase();
        if (p === 'tcp') return 'proto-tcp';
        if (p === 'udp') return 'proto-udp';
        if (p === 'icmp') return 'proto-icmp';
        if (p === 'dns') return 'proto-dns';
        return 'proto-other';
    }

    function renderPackets(packets) {
        packetBody.innerHTML = '';
        const frag = document.createDocumentFragment();

        packets.forEach((pkt, idx) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${pkt.num}</td>
                <td>${pkt.src}</td>
                <td>${pkt.dst}</td>
                <td class="${protoClass(pkt.proto)}">${pkt.proto}</td>
                <td>${pkt.len}</td>
                <td>${escHtml(pkt.info)}</td>
            `;
            tr.addEventListener('click', () => {
                packetBody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
                tr.classList.add('selected');
                showPacketDetails(pkt);
            });
            frag.appendChild(tr);
        });

        packetBody.appendChild(frag);
    }

    function showPacketDetails(pkt) {
        let html = '';
        pkt.layers.forEach(layer => {
            html += `<div class="detail-layer">`;
            html += `<div class="detail-layer-name">▸ ${layer.name}</div>`;
            for (const [key, val] of Object.entries(layer.fields)) {
                html += `<div class="detail-field"><span class="field-name">${key}:</span> <span class="field-value">${escHtml(String(val))}</span></div>`;
            }
            html += `</div>`;
        });
        packetDetails.innerHTML = html || '<span class="placeholder">No layer details available.</span>';
    }

    // ═══════════════════════════════════════════════════════════════════
    // ENDPOINTS TABLE
    // ═══════════════════════════════════════════════════════════════════

    function renderEndpoints(endpoints) {
        const body = document.getElementById('endpointsBody');
        body.innerHTML = '';
        endpoints.forEach(ep => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${ep.ip}</td>
                <td>${ep.mac}</td>
                <td>${ep.tx_pkts}</td>
                <td>${ep.rx_pkts}</td>
                <td>${formatBytes(ep.tx_bytes)}</td>
                <td>${formatBytes(ep.rx_bytes)}</td>
                <td>${ep.protocols.map(p => `<span class="${protoClass(p)}">${p}</span>`).join(' ')}</td>
            `;
            body.appendChild(tr);
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // CONVERSATIONS TABLE
    // ═══════════════════════════════════════════════════════════════════

    function renderConversations(conversations) {
        const body = document.getElementById('conversationsBody');
        body.innerHTML = '';
        conversations.forEach(conv => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${conv.addr_a}</td>
                <td>${conv.addr_b}</td>
                <td>${conv.pkts}</td>
                <td>${formatBytes(conv.bytes)}</td>
                <td>${conv.protocols.map(p => `<span class="${protoClass(p)}">${p}</span>`).join(' ')}</td>
                <td>${conv.duration}s</td>
            `;
            body.appendChild(tr);
        });
    }

    // ═══════════════════════════════════════════════════════════════════
    // TRAFFIC FLOW DIAGRAM (SVG)
    // ═══════════════════════════════════════════════════════════════════

    function renderFlowDiagram(conversations, endpoints) {
        const svg = document.getElementById('flowSvg');
        svg.innerHTML = '';

        if (!conversations.length || !endpoints.length) {
            svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#808080" font-size="14">No conversation data to visualize.</text>';
            return;
        }

        // Get unique IPs sorted by total traffic
        const ipSet = new Set();
        conversations.forEach(c => { ipSet.add(c.addr_a); ipSet.add(c.addr_b); });
        const ips = Array.from(ipSet);

        // Sort by total bytes
        const ipStats = {};
        endpoints.forEach(ep => {
            ipStats[ep.ip] = (ep.tx_bytes || 0) + (ep.rx_bytes || 0);
        });
        ips.sort((a, b) => (ipStats[b] || 0) - (ipStats[a] || 0));

        // Limit to top 15 endpoints
        const displayIps = ips.slice(0, 15);

        const colWidth = Math.max(120, Math.min(180, 1200 / displayIps.length));
        const svgWidth = Math.max(800, displayIps.length * colWidth + 100);
        const headerY = 50;
        const lineStartY = 80;

        // Calculate max packets for line thickness scaling
        const maxPkts = Math.max(...conversations.map(c => c.pkts), 1);

        // Position endpoints
        const ipPositions = {};
        displayIps.forEach((ip, i) => {
            ipPositions[ip] = 50 + i * colWidth + colWidth / 2;
        });

        let html = '';

        // Draw endpoint columns
        displayIps.forEach(ip => {
            const x = ipPositions[ip];
            const totalBytes = ipStats[ip] || 0;

            // Vertical line
            html += `<line x1="${x}" y1="${lineStartY}" x2="${x}" y2="900" stroke="#1a1a2a" stroke-width="1" stroke-dasharray="4,4"/>`;

            // IP label
            html += `<text x="${x}" y="${headerY - 15}" text-anchor="middle" fill="#00f3ff" font-size="11" font-weight="bold">${ip}</text>`;

            // Bytes label
            html += `<text x="${x}" y="${headerY}" text-anchor="middle" fill="#808080" font-size="9">${formatBytes(totalBytes)}</text>`;

            // Endpoint dot
            html += `<circle cx="${x}" cy="${lineStartY}" r="5" fill="#00f3ff" opacity="0.8"/>`;
        });

        // Draw conversation lines
        let lineY = lineStartY + 30;
        const lineSpacing = 40;

        // Sort conversations by packets (descending)
        const sortedConvs = [...conversations]
            .filter(c => ipPositions[c.addr_a] !== undefined && ipPositions[c.addr_b] !== undefined)
            .sort((a, b) => b.pkts - a.pkts)
            .slice(0, 20);

        sortedConvs.forEach(conv => {
            const x1 = ipPositions[conv.addr_a];
            const x2 = ipPositions[conv.addr_b];
            if (x1 === undefined || x2 === undefined) return;

            const thickness = Math.max(1, Math.min(6, (conv.pkts / maxPkts) * 6));

            // Color by primary protocol
            let color = '#ffcc00'; // default
            if (conv.protocols.includes('TCP')) color = '#00f3ff';
            else if (conv.protocols.includes('UDP')) color = '#bc13fe';
            else if (conv.protocols.includes('ICMP')) color = '#ff00ff';

            // Arrow line
            const midX = (x1 + x2) / 2;
            html += `<line x1="${x1}" y1="${lineY}" x2="${x2}" y2="${lineY}" stroke="${color}" stroke-width="${thickness}" opacity="0.7"/>`;

            // Arrowhead
            const arrowDir = x2 > x1 ? -1 : 1;
            html += `<polygon points="${x2},${lineY} ${x2 + arrowDir * 8},${lineY - 4} ${x2 + arrowDir * 8},${lineY + 4}" fill="${color}" opacity="0.8"/>`;

            // Label
            const label = `${conv.protocols.join('/')} ${conv.pkts}pkts`;
            html += `<text x="${midX}" y="${lineY - 6}" text-anchor="middle" fill="${color}" font-size="9" opacity="0.9">${label}</text>`;

            lineY += lineSpacing;
        });

        const svgHeight = Math.max(500, lineY + 50);
        svg.setAttribute('viewBox', `0 0 ${svgWidth} ${svgHeight}`);
        svg.style.minHeight = `${Math.min(svgHeight, 800)}px`;
        svg.innerHTML = html;
    }

    // ═══════════════════════════════════════════════════════════════════
    // REWRITER
    // ═══════════════════════════════════════════════════════════════════

    const rewriteHostsBody = document.getElementById('rewriteHostsBody');

    function populateRewriterHosts(hosts) {
        rewriteHostsBody.innerHTML = '';
        hosts.forEach(h => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${h.ip}</td>
                <td style="color: var(--text-dim)">${h.mac}</td>
                <td><input type="text" class="rewrite-input label-input" placeholder="Label..." data-host-ip="${h.ip}" data-field="label"></td>
                <td class="rewrite-arrow">&rarr;</td>
                <td>
                    <div class="input-with-picker">
                        <input type="text" class="rewrite-input" placeholder="New IP" data-host-ip="${h.ip}" data-orig-ip="${h.ip}" data-field="new_ip">
                        <button class="addr-pick-btn rewrite-addr-pick" data-target="rewrite_ip_${h.ip}" title="Pick from Address Book">&#x25BC;</button>
                    </div>
                </td>
                <td>
                    <div class="input-with-picker">
                        <input type="text" class="rewrite-input" placeholder="New MAC" data-host-mac="${h.mac}" data-orig-mac="${h.mac}" data-field="new_mac">
                        <button class="addr-pick-btn rewrite-addr-pick" data-target="rewrite_mac_${h.mac}" title="Pick from Address Book">&#x25BC;</button>
                    </div>
                </td>
            `;
            rewriteHostsBody.appendChild(tr);
        });
        // Wire up rewriter address picker buttons
        rewriteHostsBody.querySelectorAll('.rewrite-addr-pick').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                showAddressDropdown(btn.dataset.target, btn);
            });
        });
    }

    function getRewriteMaps() {
        const ipMap = {};
        const macMap = {};
        const labels = {};

        rewriteHostsBody.querySelectorAll('tr').forEach(tr => {
            const inputs = tr.querySelectorAll('.rewrite-input');
            inputs.forEach(inp => {
                const val = inp.value.trim();
                if (!val) return;
                if (inp.dataset.field === 'new_ip' && inp.dataset.origIp) {
                    ipMap[inp.dataset.origIp] = val;
                }
                if (inp.dataset.field === 'new_mac' && inp.dataset.origMac) {
                    macMap[inp.dataset.origMac] = val;
                }
                if (inp.dataset.field === 'label' && inp.dataset.hostIp) {
                    labels[inp.dataset.hostIp] = val;
                }
            });
        });

        return { ipMap, macMap, labels };
    }

    // ═══════════════════════════════════════════════════════════════════
    // DOWNLOAD REWRITTEN PCAP
    // ═══════════════════════════════════════════════════════════════════

    document.getElementById('downloadRewrittenBtn').addEventListener('click', async () => {
        const maps = getRewriteMaps();
        const ttl = document.getElementById('replayTtl').value;
        const vlan = document.getElementById('replayVlan').value;

        try {
            const resp = await fetch('/rewrite_pcap', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filepath: analysisData?.filepath,
                    ip_map: maps.ipMap,
                    mac_map: maps.macMap,
                    ttl: ttl || null,
                    vlan_id: vlan || null
                })
            });

            if (!resp.ok) {
                const err = await resp.json();
                alert(`Error: ${err.error}`);
                return;
            }

            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `rewritten_${pcapFile.files[0]?.name || 'capture.pcap'}`;
            a.click();
            URL.revokeObjectURL(url);

        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    });

    // ═══════════════════════════════════════════════════════════════════
    // REPLAY CONTROLS
    // ═══════════════════════════════════════════════════════════════════

    const startReplayBtn = document.getElementById('startReplayBtn');
    const stopReplayBtn = document.getElementById('stopReplayBtn');
    const replayStatus = document.getElementById('replayStatus');
    const replayProgress = document.getElementById('replayProgress');
    const replayMessage = document.getElementById('replayMessage');
    const replayPps = document.getElementById('replayPps');
    const replayLog = document.getElementById('replayLog');
    const loopCheckbox = document.getElementById('replayLoop');
    const loopCountInput = document.getElementById('replayLoopCount');

    loopCheckbox.addEventListener('change', () => {
        loopCountInput.classList.toggle('hidden', !loopCheckbox.checked);
    });

    document.getElementById('toggleLogBtn').addEventListener('click', () => {
        replayLog.classList.toggle('hidden');
    });

    startReplayBtn.addEventListener('click', async () => {
        const maps = getRewriteMaps();
        const iface = document.getElementById('replayInterface').value.trim();
        if (!iface) { alert('Please enter an egress interface.'); return; }

        try {
            const resp = await fetch('/replay/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    filepath: analysisData?.filepath,
                    interface: iface,
                    speed: document.getElementById('replaySpeed').value,
                    loop: loopCheckbox.checked,
                    loop_count: parseInt(loopCountInput.value) || 0,
                    ttl: document.getElementById('replayTtl').value || null,
                    vlan_id: document.getElementById('replayVlan').value || null,
                    ip_map: maps.ipMap,
                    mac_map: maps.macMap
                })
            });

            const data = await resp.json();
            if (data.error) { alert(data.error); return; }

            // Show status
            replayStatus.classList.remove('hidden');
            startReplayBtn.classList.add('hidden');
            stopReplayBtn.classList.remove('hidden');

            // Start SSE
            startReplaySSE();

        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    });

    stopReplayBtn.addEventListener('click', async () => {
        await fetch('/replay/stop', { method: 'POST' });
    });

    function startReplaySSE() {
        if (statusEventSource) statusEventSource.close();
        statusEventSource = new EventSource('/replay/status');

        statusEventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            replayMessage.textContent = data.message;
            replayPps.textContent = `${data.pps} pps`;

            if (data.total > 0) {
                const pct = Math.round((data.progress / data.total) * 100);
                replayProgress.style.width = `${pct}%`;
            }

            // Update log
            replayLog.innerHTML = data.logs.map(l => `<div class="log-line">${escHtml(l)}</div>`).join('');
            replayLog.scrollTop = replayLog.scrollHeight;

            if (!data.is_running) {
                statusEventSource.close();
                statusEventSource = null;
                startReplayBtn.classList.remove('hidden');
                stopReplayBtn.classList.add('hidden');
            }
        };

        statusEventSource.onerror = () => {
            statusEventSource.close();
            statusEventSource = null;
            startReplayBtn.classList.remove('hidden');
            stopReplayBtn.classList.add('hidden');
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // TRAFFIC GENERATOR
    // ═══════════════════════════════════════════════════════════════════

    const genStatus = document.getElementById('genStatus');
    const genProgress = document.getElementById('genProgress');
    const genMessage = document.getElementById('genMessage');
    const genPps = document.getElementById('genPps');

    document.querySelectorAll('.gen-run-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const card = btn.closest('.gen-card');
            const type = card.dataset.type;
            const isAdversary = type === 'adversary';
            const protoOrSim = isAdversary ? card.dataset.sim : card.dataset.proto;

            // Gather common settings
            const srcIpEl = document.getElementById('genSrcIp');
            const dstIpEl = document.getElementById('genDstIp');
            const payload = {
                src_ip: srcIpEl.value,
                dst_ip: dstIpEl.value,
                interface: document.getElementById('genInterface').value,
                c2_host: document.getElementById('genC2Host').value,
                src_mac: srcIpEl.dataset.mac || null,
                dst_mac: dstIpEl.dataset.mac || null,
            };

            // Gather card-specific settings
            card.querySelectorAll('[data-field]').forEach(inp => {
                payload[inp.dataset.field] = inp.value;
            });

            if (isAdversary) {
                payload.simulation = protoOrSim;
            } else {
                payload.protocol = protoOrSim;
            }

            const url = isAdversary ? '/generate/adversary' : '/generate/protocol';

            try {
                const resp = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await resp.json();
                if (data.error) { alert(data.error); return; }

                genStatus.classList.remove('hidden');
                startGenSSE();

            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        });
    });

    document.getElementById('genStopBtn').addEventListener('click', async () => {
        await fetch('/replay/stop', { method: 'POST' }); // Reuses same stop endpoint
    });

    function startGenSSE() {
        if (statusEventSource) statusEventSource.close();
        statusEventSource = new EventSource('/replay/status');

        statusEventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            genMessage.textContent = data.message;
            genPps.textContent = `${data.pps} pps`;

            if (data.total > 0) {
                const pct = Math.round((data.progress / data.total) * 100);
                genProgress.style.width = `${pct}%`;
            }

            if (!data.is_running) {
                statusEventSource.close();
                statusEventSource = null;
            }
        };

        statusEventSource.onerror = () => {
            statusEventSource.close();
            statusEventSource = null;
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // PROFILES
    // ═══════════════════════════════════════════════════════════════════

    const profileList = document.getElementById('profileList');
    const profileName = document.getElementById('profileName');

    async function loadProfiles() {
        try {
            const resp = await fetch('/profiles');
            const profiles = await resp.json();

            if (!profiles.length) {
                profileList.innerHTML = '<div class="placeholder">No saved profiles yet.</div>';
                return;
            }

            profileList.innerHTML = '';
            profiles.forEach(p => {
                const div = document.createElement('div');
                div.className = 'profile-item';
                div.innerHTML = `
                    <div>
                        <div class="profile-name">${escHtml(p.name)}</div>
                        <div class="profile-meta">${p.rules_count} rules · ${p.labels_count} labels · ${p.modified?.split('T')[0] || ''}</div>
                    </div>
                    <div class="profile-actions">
                        <button class="btn btn-sm btn-ghost profile-load-btn" data-id="${p.id}">Load</button>
                        <button class="btn btn-sm btn-ghost profile-export-btn" data-id="${p.id}">Export</button>
                        <button class="btn btn-sm btn-danger profile-delete-btn" data-id="${p.id}">✕</button>
                    </div>
                `;
                profileList.appendChild(div);
            });

            // Wire up buttons
            profileList.querySelectorAll('.profile-load-btn').forEach(btn => {
                btn.addEventListener('click', () => loadProfile(btn.dataset.id));
            });
            profileList.querySelectorAll('.profile-export-btn').forEach(btn => {
                btn.addEventListener('click', () => exportProfile(btn.dataset.id));
            });
            profileList.querySelectorAll('.profile-delete-btn').forEach(btn => {
                btn.addEventListener('click', () => deleteProfile(btn.dataset.id));
            });

        } catch (err) {
            console.error('Failed to load profiles:', err);
        }
    }

    document.getElementById('saveProfileBtn').addEventListener('click', async () => {
        const name = profileName.value.trim();
        if (!name) { alert('Please enter a profile name.'); return; }

        const maps = getRewriteMaps();
        const profile = {
            name: name,
            labels: maps.labels,
            rewrite_rules: {
                ip_map: maps.ipMap,
                mac_map: maps.macMap,
                port_map: {}
            },
            replay_settings: {
                interface: document.getElementById('replayInterface').value,
                speed: document.getElementById('replaySpeed').value,
                loop: loopCheckbox.checked,
                loop_count: parseInt(loopCountInput.value) || 0,
                ttl: document.getElementById('replayTtl').value || null,
                vlan_id: document.getElementById('replayVlan').value || null
            },
            generator_presets: {
                src_ip: document.getElementById('genSrcIp').value,
                dst_ip: document.getElementById('genDstIp').value,
                interface: document.getElementById('genInterface').value,
                c2_host: document.getElementById('genC2Host').value,
            }
        };

        try {
            await fetch('/profiles', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(profile)
            });
            loadProfiles();
            profileName.value = '';
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    });

    async function loadProfile(id) {
        try {
            const resp = await fetch(`/profiles/${id}`);
            const profile = await resp.json();

            // Apply rewrite rules
            if (profile.rewrite_rules) {
                const ipMap = profile.rewrite_rules.ip_map || {};
                const macMap = profile.rewrite_rules.mac_map || {};
                rewriteHostsBody.querySelectorAll('tr').forEach(tr => {
                    const inputs = tr.querySelectorAll('.rewrite-input');
                    inputs.forEach(inp => {
                        if (inp.dataset.field === 'new_ip' && ipMap[inp.dataset.origIp]) {
                            inp.value = ipMap[inp.dataset.origIp];
                        }
                        if (inp.dataset.field === 'new_mac' && macMap[inp.dataset.origMac]) {
                            inp.value = macMap[inp.dataset.origMac];
                        }
                    });
                });
            }

            // Apply labels
            if (profile.labels) {
                rewriteHostsBody.querySelectorAll('.label-input').forEach(inp => {
                    if (profile.labels[inp.dataset.hostIp]) {
                        inp.value = profile.labels[inp.dataset.hostIp];
                    }
                });
            }

            // Apply replay settings
            if (profile.replay_settings) {
                const rs = profile.replay_settings;
                if (rs.interface) document.getElementById('replayInterface').value = rs.interface;
                if (rs.speed) document.getElementById('replaySpeed').value = rs.speed;
                loopCheckbox.checked = rs.loop || false;
                loopCountInput.classList.toggle('hidden', !rs.loop);
                if (rs.loop_count) loopCountInput.value = rs.loop_count;
                if (rs.ttl) document.getElementById('replayTtl').value = rs.ttl;
                if (rs.vlan_id) document.getElementById('replayVlan').value = rs.vlan_id;
            }

            // Apply generator presets
            if (profile.generator_presets) {
                const gp = profile.generator_presets;
                if (gp.src_ip) document.getElementById('genSrcIp').value = gp.src_ip;
                if (gp.dst_ip) document.getElementById('genDstIp').value = gp.dst_ip;
                if (gp.interface) document.getElementById('genInterface').value = gp.interface;
                if (gp.c2_host) document.getElementById('genC2Host').value = gp.c2_host;
            }

            alert(`Profile "${profile.name}" loaded.`);
            switchTab('rewriter');

        } catch (err) {
            alert(`Error loading profile: ${err.message}`);
        }
    }

    async function exportProfile(id) {
        try {
            const resp = await fetch(`/profiles/export/${id}`);
            const profile = await resp.json();
            const blob = new Blob([JSON.stringify(profile, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${profile.name.replace(/\s+/g, '_')}.json`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    }

    async function deleteProfile(id) {
        if (!confirm('Delete this profile?')) return;
        try {
            await fetch(`/profiles/${id}`, { method: 'DELETE' });
            loadProfiles();
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    }

    // Import
    const importProfileBtn = document.getElementById('importProfileBtn');
    const importProfileFile = document.getElementById('importProfileFile');

    importProfileBtn.addEventListener('click', () => importProfileFile.click());
    importProfileFile.addEventListener('change', async () => {
        if (!importProfileFile.files.length) return;
        try {
            const text = await importProfileFile.files[0].text();
            const data = JSON.parse(text);
            await fetch('/profiles/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            loadProfiles();
            importProfileFile.value = '';
        } catch (err) {
            alert(`Error importing: ${err.message}`);
        }
    });

    // ═══════════════════════════════════════════════════════════════════
    // ADDRESS BOOK
    // ═══════════════════════════════════════════════════════════════════

    let addressBookCache = [];

    async function loadAddresses() {
        try {
            const resp = await fetch('/addresses');
            addressBookCache = await resp.json();
            renderAddressList();
        } catch (err) {
            console.error('Failed to load addresses:', err);
        }
    }

    function renderAddressList() {
        const list = document.getElementById('addressList');
        if (!addressBookCache.length) {
            list.innerHTML = '<div class="placeholder">No saved addresses yet.</div>';
            return;
        }
        list.innerHTML = '';
        addressBookCache.forEach(addr => {
            const div = document.createElement('div');
            div.className = 'address-item';
            div.innerHTML = `
                <div class="addr-info">
                    <span class="addr-name">${escHtml(addr.name || 'Unnamed')}</span>
                    <span class="addr-ip">${escHtml(addr.ip)}</span>
                    <span class="addr-mac">${escHtml(addr.mac || '-')}</span>
                </div>
                <button class="btn btn-sm btn-danger addr-delete-btn" data-id="${addr.id}">&times;</button>
            `;
            list.appendChild(div);
        });
        list.querySelectorAll('.addr-delete-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                await fetch(`/addresses/${btn.dataset.id}`, { method: 'DELETE' });
                loadAddresses();
            });
        });
    }

    document.getElementById('addAddressBtn').addEventListener('click', async () => {
        const name = document.getElementById('addrName').value.trim();
        const ip = document.getElementById('addrIp').value.trim();
        const mac = document.getElementById('addrMac').value.trim();
        if (!ip) { alert('IP address is required.'); return; }
        try {
            await fetch('/addresses', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, ip, mac })
            });
            document.getElementById('addrName').value = '';
            document.getElementById('addrIp').value = '';
            document.getElementById('addrMac').value = '';
            loadAddresses();
        } catch (err) {
            alert(`Error: ${err.message}`);
        }
    });

    // Address picker dropdown
    function showAddressDropdown(targetType, anchorEl) {
        closeAddressDropdown();
        if (!addressBookCache.length) return;

        const dropdown = document.createElement('div');
        dropdown.className = 'addr-dropdown';
        dropdown.id = 'activeAddrDropdown';

        addressBookCache.forEach(addr => {
            const item = document.createElement('div');
            item.className = 'addr-dropdown-item';
            item.innerHTML = `
                <span class="addr-drop-name">${escHtml(addr.name || 'Unnamed')}</span>
                <span class="addr-drop-detail">${escHtml(addr.ip)}${addr.mac ? ' / ' + escHtml(addr.mac) : ''}</span>
            `;
            item.addEventListener('click', () => {
                applyAddressPick(targetType, addr);
                closeAddressDropdown();
            });
            dropdown.appendChild(item);
        });

        const rect = anchorEl.getBoundingClientRect();
        dropdown.style.top = `${rect.bottom + 2}px`;
        dropdown.style.left = `${rect.left}px`;
        document.body.appendChild(dropdown);

        setTimeout(() => {
            document.addEventListener('click', onDropdownOutsideClick);
        }, 0);
    }

    function applyAddressPick(targetType, addr) {
        if (targetType === 'src') {
            const el = document.getElementById('genSrcIp');
            el.value = addr.ip;
            el.dataset.mac = addr.mac || '';
        } else if (targetType === 'dst') {
            const el = document.getElementById('genDstIp');
            el.value = addr.ip;
            el.dataset.mac = addr.mac || '';
        } else if (targetType === 'c2') {
            document.getElementById('genC2Host').value = addr.ip;
        } else if (targetType.startsWith('rewrite_ip_')) {
            const origIp = targetType.replace('rewrite_ip_', '');
            const input = rewriteHostsBody.querySelector(
                `.rewrite-input[data-field="new_ip"][data-orig-ip="${origIp}"]`
            );
            if (input) input.value = addr.ip;
        } else if (targetType.startsWith('rewrite_mac_')) {
            const origMac = targetType.replace('rewrite_mac_', '');
            const input = rewriteHostsBody.querySelector(
                `.rewrite-input[data-field="new_mac"][data-orig-mac="${origMac}"]`
            );
            if (input) input.value = addr.mac || '';
        }
    }

    function closeAddressDropdown() {
        const existing = document.getElementById('activeAddrDropdown');
        if (existing) existing.remove();
        document.removeEventListener('click', onDropdownOutsideClick);
    }

    function onDropdownOutsideClick(e) {
        const dropdown = document.getElementById('activeAddrDropdown');
        if (dropdown && !dropdown.contains(e.target)) {
            closeAddressDropdown();
        }
    }

    // Wire up generator settings picker buttons
    document.querySelectorAll('.addr-pick-btn:not(.rewrite-addr-pick)').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            showAddressDropdown(btn.dataset.target, btn);
        });
    });

    // ═══════════════════════════════════════════════════════════════════
    // UTILITIES
    // ═══════════════════════════════════════════════════════════════════

    function escHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // ═══════════════════════════════════════════════════════════════════
    // INIT
    // ═══════════════════════════════════════════════════════════════════

    loadProfiles();
    loadAddresses();

});
