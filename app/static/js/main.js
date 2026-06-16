document.addEventListener('DOMContentLoaded', function () {
    let statusInterval, trafficChart, chartTime = 0, currentTab = 'replayer';
    const tabReplayer = document.getElementById('tab-replayer'), tabGenerator = document.getElementById('tab-generator');
    const replayerPane = document.getElementById('replayer-pane'), generatorPane = document.getElementById('generator-pane');

    const tabViewer = document.getElementById('tab-viewer');
    const viewerPane = document.getElementById('viewer-pane');
    const viewerPlaceholder = document.getElementById('viewer-placeholder');
    const viewerNavToReplayer = document.getElementById('viewer-nav-to-replayer');

    const replayerForm = document.getElementById('replayerForm'), generatorForm = document.getElementById('generatorForm');
    const statusContainer = document.getElementById('statusContainer'), statusTitle = document.getElementById('statusTitle');
    const stopBtn = document.getElementById('stopBtn'), progressBar = document.getElementById('progressBar');
    const statusMessage = document.getElementById('statusMessage'), toggleConsoleBtn = document.getElementById('toggleConsoleBtn');
    const consoleWrapper = document.getElementById('consoleWrapper'), consoleOutput = document.getElementById('consoleOutput');
    const consoleArrow = document.getElementById('consoleArrow');
    const pcapFileInput = document.getElementById('pcapFile');

    const discoveredHostsTable = document.getElementById('discoveredHostsTable');
    const discoveredHostsBody = document.getElementById('discoveredHostsBody');

    const packetViewer = document.getElementById('packetViewer');
    const packetViewerBody = document.getElementById('packetViewerBody');
    const packetDetails = document.getElementById('packetDetails');
    const analysisStatus = document.getElementById('analysisStatus');

    // New UI Elements
    const viewerModeSelect = document.getElementById('viewerModeSelect');
    const packetListView = document.getElementById('packetListView');
    const endpointsView = document.getElementById('endpointsView');
    const conversationsView = document.getElementById('conversationsView');
    const endpointsBody = document.getElementById('endpointsBody');
    const conversationsBody = document.getElementById('conversationsBody');
    const exportConfigBtn = document.getElementById('exportConfigBtn');
    const importConfigBtn = document.getElementById('importConfigBtn');
    const importFile = document.getElementById('importFile');

    // --- Config Management ---
    const configNameInput = document.getElementById('configName');
    const saveConfigBtn = document.getElementById('saveConfigBtn');
    const configSelect = document.getElementById('configSelect');
    const loadConfigBtn = document.getElementById('loadConfigBtn');
    const deleteConfigBtn = document.getElementById('deleteConfigBtn');

    // --- Asset Management ---
    let assets = [];
    const addAssetBtn = document.getElementById('addAssetBtn');
    const assetNameInput = document.getElementById('assetName');
    const assetIpInput = document.getElementById('assetIp');
    const assetMacInput = document.getElementById('assetMac');
    const assetListDiv = document.getElementById('assetList');

    // Global state for packets
    let currentPackets = [];
    let currentEndpoints = [];
    let currentConversations = [];
    let selectedPacket = null;

    // View Switching
    if (viewerModeSelect) {
        viewerModeSelect.addEventListener('change', () => {
            const mode = viewerModeSelect.value;
            console.log("Switching view to:", mode);

            packetListView.classList.toggle('hidden', mode !== 'packets');
            endpointsView.classList.toggle('hidden', mode !== 'endpoints');
            conversationsView.classList.toggle('hidden', mode !== 'conversations');

            // Hide details pane if not in packet mode
            const detailsPane = document.getElementById('packetDetailsPane');
            if (detailsPane) {
                detailsPane.classList.toggle('hidden', mode !== 'packets');
            }
        });
    }

    const viewStatsBtn = document.getElementById('viewStatsBtn');
    if (viewStatsBtn) {
        viewStatsBtn.addEventListener('click', () => {
            switchTab('viewer');
            if (viewerModeSelect) {
                viewerModeSelect.value = 'endpoints';
                viewerModeSelect.dispatchEvent(new Event('change'));
            }
        });
    }

    async function fetchAssets() {
        try {
            const response = await fetch('/api/assets');
            if (!response.ok) throw new Error('Failed to fetch assets');
            assets = await response.json();
            renderAssets();
        } catch (error) {
            console.error("Error fetching assets:", error);
            assetListDiv.innerHTML = `<span class="text-pink-500">Error loading assets.</span>`;
        }
    }

    function populateAllAssetSelects() {
        const allSelects = document.querySelectorAll('.asset-select');
        allSelects.forEach(sel => {
            const currentVal = sel.value;
            sel.innerHTML = '<option value="">Select Asset...</option>';
            assets.forEach(asset => {
                const option = document.createElement('option');
                option.value = asset.id;
                option.textContent = asset.name;
                sel.appendChild(option);
            });
            sel.value = currentVal;
        });
    }

    function renderAssets() {
        assetListDiv.innerHTML = '';
        assets.forEach(asset => {
            const assetItem = document.createElement('div');
            assetItem.className = 'text-xs flex justify-between items-center p-1 bg-black/30';
            assetItem.innerHTML = `<span><strong class="text-cyan-300">${asset.name}:</strong> ${asset.ip} / ${asset.mac}</span><button data-id="${asset.id}" class="asset-delete-btn text-pink-500 font-bold text-lg">&times;</button>`;
            assetListDiv.appendChild(assetItem);
        });
        populateAllAssetSelects();
        document.querySelectorAll('.asset-delete-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const assetId = e.target.dataset.id;
                try {
                    const response = await fetch(`/api/assets/${assetId}`, { method: 'DELETE' });
                    if (!response.ok) throw new Error('Failed to delete asset');
                    fetchAssets();
                } catch (error) {
                    console.error("Error deleting asset:", error);
                    alert("Error deleting asset.");
                }
            });
        });
    }

    addAssetBtn.addEventListener('click', async () => {
        const name = assetNameInput.value.trim();
        const ip = assetIpInput.value.trim();
        const mac = assetMacInput.value.trim();
        if (name && ip && mac) {
            try {
                const response = await fetch('/api/assets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name, ip, mac })
                });
                if (!response.ok) {
                    const err = await response.json();
                    throw new Error(err.error || 'Failed to add asset');
                }
                assetNameInput.value = assetIpInput.value = assetMacInput.value = '';
                fetchAssets();
            } catch (error) {
                console.error("Error adding asset:", error);
                alert(`Error: ${error.message}`);
            }
        } else {
            alert('Please fill out all asset fields.');
        }
    });

    document.body.addEventListener('change', (e) => {
        if (e.target.classList.contains('asset-select') && e.target.value !== '') {
            const asset = assets.find(a => a.id == e.target.value);
            if (!asset) return;

            if (e.target.closest('form').id === 'generatorForm') {
                const targetBase = e.target.dataset.assetTarget;
                const form = e.target.closest('form');
                form.querySelector(`input[name="${targetBase}_ip"]`).value = asset.ip;
                form.querySelector(`input[name="${targetBase}_mac"]`).value = asset.mac;
            } else {
                const input = e.target.nextElementSibling;
                const targetInputType = input.dataset.validate;
                if (targetInputType === 'ip') input.value = asset.ip;
                if (targetInputType === 'mac') input.value = asset.mac;
            }
            e.target.value = '';
            validateAllInputs();
        }
    });

    // --- Config Management Logic ---
    async function fetchConfigs() {
        try {
            const response = await fetch('/api/replay_configs');
            if (!response.ok) throw new Error('Failed to fetch configs');
            const configs = await response.json();
            configSelect.innerHTML = '<option value="">Select a config...</option>';
            configs.forEach(config => {
                const option = document.createElement('option');
                option.value = config.id;
                option.textContent = config.name;
                configSelect.appendChild(option);
            });
        } catch (error) {
            console.error("Error fetching configs:", error);
            configSelect.innerHTML = '<option value="">Error loading configs</option>';
        }
    }

    saveConfigBtn.addEventListener('click', async () => {
        const name = configNameInput.value.trim();
        if (!name) {
            alert('Please enter a name for the configuration.');
            return;
        }

        const getMaps = (type) => {
            const container = document.getElementById(`${type}MappingsContainer`);
            return Array.from(container.children).map(row => ({
                original: row.querySelector(`input[name="${type}_original"]`).value,
                new: row.querySelector(`input[name="${type}_new"]`).value
            })).filter(item => item.original && item.new);
        };

        const configData = {
            name: name,
            interface: replayerForm.elements['interface'].value,
            replay_speed: replayerForm.elements['replay_speed'].value,
            loop_replay: replayerForm.elements['loop_replay'].checked,
            loop_count: replayerForm.elements['loop_count'].value ? parseInt(replayerForm.elements['loop_count'].value) : 0,
            ttl: replayerForm.elements['ttl'].value ? parseInt(replayerForm.elements['ttl'].value) : null,
            vlan_id: replayerForm.elements['vlan_id'].value ? parseInt(replayerForm.elements['vlan_id'].value) : null,
            ip_map: getMaps('ip'),
            mac_map: getMaps('mac'),
            port_map: getMaps('port')
        };

        try {
            const response = await fetch('/api/replay_configs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(configData)
            });
            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.error || 'Failed to save config');
            }
            alert('Configuration saved successfully!');
            fetchConfigs();
        } catch (error) {
            console.error("Error saving config:", error);
            alert(`Error: ${error.message}`);
        }
    });

    loadConfigBtn.addEventListener('click', async () => {
        const configId = configSelect.value;
        if (!configId) {
            alert('Please select a configuration to load.');
            return;
        }
        try {
            const response = await fetch(`/api/replay_configs/${configId}`);
            if (!response.ok) throw new Error('Failed to load config');
            const config = await response.json();

            replayerForm.elements['interface'].value = config.interface || '';
            replayerForm.elements['replay_speed'].value = config.replay_speed || 'original';
            replayerForm.elements['loop_replay'].checked = config.loop_replay;
            loopCountContainer.classList.toggle('hidden', !config.loop_replay);
            replayerForm.elements['loop_count'].value = config.loop_count || '';
            replayerForm.elements['ttl'].value = config.ttl || '';
            replayerForm.elements['vlan_id'].value = config.vlan_id || '';
            configNameInput.value = config.name;

            const populateMaps = (type, maps) => {
                const container = document.getElementById(`${type}MappingsContainer`);
                container.innerHTML = '';
                if (maps) {
                    maps.forEach(item => {
                        addMappingRow(container, type, item.original);
                        const newRow = container.lastElementChild;
                        newRow.querySelector(`input[name="${type}_new"]`).value = item.new;
                    });
                }
            };
            populateMaps('ip', config.ip_map);
            populateMaps('mac', config.mac_map);
            populateMaps('port', config.port_map);

            alert('Configuration loaded.');
            validateAllInputs();
        } catch (error) {
            console.error("Error loading config:", error);
            alert('Error loading configuration.');
        }
    });

    deleteConfigBtn.addEventListener('click', async () => {
        const configId = configSelect.value;
        if (!configId) {
            alert('Please select a configuration to delete.');
            return;
        }
        if (!confirm('Are you sure you want to delete this configuration?')) return;

        try {
            const response = await fetch(`/api/replay_configs/${configId}`, { method: 'DELETE' });
            if (!response.ok) throw new Error('Failed to delete config');
            alert('Configuration deleted.');
            fetchConfigs();
        } catch (error) {
            console.error("Error deleting config:", error);
            alert('Error deleting configuration.');
        }
    });

    function switchTab(activeTab) {
        currentTab = activeTab;
        tabReplayer.classList.toggle('active', activeTab === 'replayer');
        tabGenerator.classList.toggle('active', activeTab === 'generator');
        tabViewer.classList.toggle('active', activeTab === 'viewer');

        replayerPane.classList.toggle('hidden', activeTab !== 'replayer');
        generatorPane.classList.toggle('hidden', activeTab !== 'generator');
        viewerPane.classList.toggle('hidden', activeTab !== 'viewer');
    }
    tabReplayer.addEventListener('click', () => switchTab('replayer'));
    tabGenerator.addEventListener('click', () => switchTab('generator'));
    tabViewer.addEventListener('click', () => switchTab('viewer'));
    viewerNavToReplayer.addEventListener('click', () => switchTab('replayer'));

    function addMappingRow(container, type, val1 = '') {
        const p1 = `Original ${type.toUpperCase()}`, p2 = `New ${type.toUpperCase()}`;
        const row = document.createElement('div');
        row.className = 'grid grid-cols-[1fr_auto_1fr_auto] gap-2 items-center mb-2';

        if (type === 'port') {
            row.innerHTML = `
                <input type="number" name="port_original" placeholder="${p1}" value="${val1}" class="w-full form-input p-2 text-sm">
                <span class="text-cyan-400 font-bold text-xl">-></span>
                <input type="number" name="port_new" placeholder="${p2}" class="w-full form-input p-2 text-sm">
                <button type="button" class="remove-btn text-pink-500 hover:text-pink-400 font-bold text-2xl">&times;</button>
            `;
        } else {
            row.innerHTML = `
                <div class="flex w-full"><select data-asset-target="map" class="asset-select form-input p-2 w-1/3 text-sm"></select><input type="text" name="${type}_original" placeholder="${p1}" value="${val1}" class="w-2/3 form-input p-2 text-sm" data-validate="${type}"></div>
                <span class="text-cyan-400 font-bold text-xl">-></span>
                <div class="flex w-full"><select data-asset-target="map" class="asset-select form-input p-2 w-1/3 text-sm"></select><input type="text" name="${type}_new" placeholder="${p2}" class="w-2/3 form-input p-2 text-sm" data-validate="${type}"></div>
                <button type="button" class="remove-btn text-pink-500 hover:text-pink-400 font-bold text-2xl">&times;</button>
            `;
        }
        container.appendChild(row);
        populateAllAssetSelects();
        row.querySelector('.remove-btn').addEventListener('click', () => row.remove());
        validateAllInputs();
    }
    document.querySelectorAll('button[data-action="add-map"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.dataset.type;
            const container = document.getElementById(`${type}MappingsContainer`);
            addMappingRow(container, type);
        });
    });

    pcapFileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        analysisStatus.textContent = 'Analyzing PCAP...';
        analysisStatus.classList.remove('hidden', 'text-red-500');

        discoveredHostsTable.classList.add('hidden');
        packetViewer.classList.add('hidden');
        viewerPlaceholder.classList.remove('hidden');

        discoveredHostsBody.innerHTML = '';
        packetViewerBody.innerHTML = '';
        packetDetails.innerHTML = '<div class="text-gray-500 italic">Select a packet to view details...</div>';

        const formData = new FormData();
        formData.append('pcapFile', file);

        try {
            const response = await fetch('/analyze_pcap', { method: 'POST', body: formData });
            const data = await response.json();

            if (response.ok) {
                const adversary_ip = data.adversary;
                data.hosts.forEach(host => {
                    const row = document.createElement('tr');
                    row.className = 'border-t border-cyan-900/50';

                    let ipCell = `<td>${host.ip}</td>`;
                    if (host.ip === adversary_ip) {
                        ipCell = `<td>${host.ip} <span class="adversary-tag">// ADVERSARY?</span></td>`;
                    }

                    row.innerHTML = `
                        ${ipCell}
                        <td class="p-2">${host.mac}</td>
                        <td class="p-2 text-center">
                            <button type="button" data-ip="${host.ip}" data-mac="${host.mac}" class="add-host-btn">+</button>
                        </td>
                    `;
                    discoveredHostsBody.appendChild(row);
                });
                discoveredHostsTable.classList.remove('hidden');

                console.log("Packets:", data.packets.length);
                console.log("Endpoints:", data.endpoints ? data.endpoints.length : 0);
                console.log("Conversations:", data.conversations ? data.conversations.length : 0);

                currentPackets = data.packets;
                currentEndpoints = data.endpoints || [];
                currentConversations = data.conversations || [];

                renderPacketList(currentPackets);
                renderEndpoints(currentEndpoints);
                renderConversations(currentConversations);

                // Reset to packet view
                if (viewerModeSelect) {
                    viewerModeSelect.value = 'packets';
                    packetListView.classList.remove('hidden');
                    endpointsView.classList.add('hidden');
                    conversationsView.classList.add('hidden');
                }

                packetViewer.classList.remove('hidden');
                viewerPlaceholder.classList.add('hidden');

                analysisStatus.classList.add('hidden');

            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            analysisStatus.textContent = `Error: ${error.message}`;
            analysisStatus.classList.add('text-pink-500');
            discoveredHostsBody.innerHTML = `<span class="text-pink-500">Error: ${error.message}</span>`;
        }
    });

    // --- Packet Viewer Functions ---
    const escapeHTML = str => (str ?? '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    function renderPacketList(packets) {
        packetViewerBody.innerHTML = '';
        packets.forEach((packet, index) => {
            const row = document.createElement('tr');
            row.className = 'border-t border-cyan-900/50 packet-row hover:bg-cyan-900/20 cursor-pointer';
            row.dataset.index = index;
            row.innerHTML = `
                <td class="p-2">${packet.num}</td>
                <td class="p-2">${escapeHTML(packet.src)}</td>
                <td class="p-2">${escapeHTML(packet.dst)}</td>
                <td class="p-2">${escapeHTML(packet.proto)}</td>
                <td class="p-2">${escapeHTML(packet.info)}</td>
            `;
            row.addEventListener('click', () => selectPacket(row, packet));
            row.addEventListener('contextmenu', (e) => showContextMenu(e, packet));
            packetViewerBody.appendChild(row);
        });
    }

    function selectPacket(row, packet) {
        document.querySelectorAll('.packet-row').forEach(r => {
            r.classList.remove('selected');
            r.classList.remove('bg-cyan-900/40');
        });
        row.classList.add('selected');
        row.classList.add('bg-cyan-900/40');
        selectedPacket = packet;
        renderPacketDetails(packet);
    }

    function renderPacketDetails(packet) {
        packetDetails.innerHTML = '';

        if (!packet.layers || packet.layers.length === 0) {
            packetDetails.innerHTML = '<div class="text-gray-500">No detailed info available.</div>';
            return;
        }

        packet.layers.forEach(layer => {
            const layerDiv = document.createElement('div');
            layerDiv.className = 'mb-2';

            const header = document.createElement('div');
            header.className = 'detail-header text-cyan-400 font-bold cursor-pointer select-none';
            header.textContent = `> ${layer.name}`;

            const content = document.createElement('div');
            content.className = 'detail-content ml-4 hidden'; // Hidden by default

            for (const [key, value] of Object.entries(layer.fields)) {
                const item = document.createElement('div');
                item.className = 'detail-item text-xs font-mono';
                item.innerHTML = `<span class="text-cyan-600">${key}:</span> <span class="text-gray-400 break-all">${value}</span>`;
                content.appendChild(item);
            }

            header.addEventListener('click', () => {
                content.classList.toggle('hidden');
                header.textContent = content.classList.contains('hidden') ? `> ${layer.name}` : `v ${layer.name}`;
            });

            layerDiv.appendChild(header);
            layerDiv.appendChild(content);
            packetDetails.appendChild(layerDiv);
        });
    }

    function renderEndpoints(endpoints) {
        endpointsBody.innerHTML = '';
        endpoints.forEach(ep => {
            const row = document.createElement('tr');
            row.className = 'border-t border-cyan-900/50 hover:bg-cyan-900/20 cursor-pointer';
            row.innerHTML = `
                <td class="p-2">${ep.ip}</td>
                <td class="p-2">${ep.tx_pkts}</td>
                <td class="p-2">${ep.rx_pkts}</td>
                <td class="p-2">${ep.tx_bytes}</td>
                <td class="p-2">${ep.rx_bytes}</td>
            `;
            // Reuse context menu for quick rewriting
            row.addEventListener('contextmenu', (e) => showContextMenu(e, { src: ep.ip, dst: ep.ip }));
            endpointsBody.appendChild(row);
        });
    }

    function renderConversations(conversations) {
        conversationsBody.innerHTML = '';
        conversations.forEach(conv => {
            const row = document.createElement('tr');
            row.className = 'border-t border-cyan-900/50 hover:bg-cyan-900/20 cursor-pointer';
            row.innerHTML = `
                <td class="p-2">${conv.ip_a}</td>
                <td class="p-2">${conv.ip_b}</td>
                <td class="p-2">${conv.pkts}</td>
                <td class="p-2">${conv.bytes}</td>
                <td class="p-2">${conv.duration.toFixed(4)}</td>
            `;
            row.addEventListener('contextmenu', (e) => showContextMenu(e, { src: conv.ip_a, dst: conv.ip_b }));
            conversationsBody.appendChild(row);
        });
    }

    // Export/Import Handlers
    if (exportConfigBtn) {
        exportConfigBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/api/config/export', { method: 'POST' });
                if (!response.ok) throw new Error('Export failed');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'netrunner_backup.json';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
            } catch (error) {
                alert('Export failed: ' + error.message);
            }
        });
    }

    if (importConfigBtn && importFile) {
        importConfigBtn.addEventListener('click', () => importFile.click());
        importFile.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            const formData = new FormData();
            formData.append('configFile', file);

            try {
                const response = await fetch('/api/config/import', { method: 'POST', body: formData });
                const result = await response.json();
                if (response.ok) {
                    alert(result.message);
                    fetchAssets();
                    fetchConfigs();
                } else {
                    throw new Error(result.error);
                }
            } catch (error) {
                alert('Import failed: ' + error.message);
            }
            importFile.value = '';
        });
    }

    // --- Context Menu ---
    const contextMenu = document.getElementById('contextMenu');
    let contextMenuPacket = null;

    function showContextMenu(e, packet) {
        e.preventDefault();
        contextMenuPacket = packet;
        contextMenu.style.top = `${e.pageY}px`;
        contextMenu.style.left = `${e.pageX}px`;
        contextMenu.style.display = 'block';
    }

    document.addEventListener('click', (e) => {
        if (!contextMenu.contains(e.target)) {
            contextMenu.style.display = 'none';
        }
    });

    document.getElementById('ctxRewriteSrcIp').addEventListener('click', () => {
        if (contextMenuPacket) {
            addMappingRow(document.getElementById('ipMappingsContainer'), 'ip', contextMenuPacket.src);
            switchTab('replayer');
        }
        contextMenu.style.display = 'none';
    });
    document.getElementById('ctxRewriteDstIp').addEventListener('click', () => {
        if (contextMenuPacket) {
            addMappingRow(document.getElementById('ipMappingsContainer'), 'ip', contextMenuPacket.dst);
            switchTab('replayer');
        }
        contextMenu.style.display = 'none';
    });
    // Add other context menu handlers if needed


    document.body.addEventListener('click', (e) => {
        if (e.target.classList.contains('add-host-btn')) {
            const ip = e.target.dataset.ip;
            const mac = e.target.dataset.mac;

            if (ip && ip !== 'N/A') {
                addMappingRow(document.getElementById('ipMappingsContainer'), 'ip', ip);
            }
            if (mac && mac !== 'N/A') {
                addMappingRow(document.getElementById('macMappingsContainer'), 'mac', mac);
            }
        }
    });

    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;

    function validateInput(input) {
        const type = input.dataset.validate;
        if (!type) return;

        const regex = type === 'ip' ? ipRegex : macRegex;
        if (!input.value && !input.required) {
            input.classList.remove('invalid');
            return;
        }

        if (regex.test(input.value)) {
            input.classList.remove('invalid');
        } else {
            input.classList.add('invalid');
        }
    }

    function validateAllInputs() {
        document.querySelectorAll('input[data-validate]').forEach(validateInput);
    }

    document.body.addEventListener('input', e => {
        if (e.target.matches('input[data-validate]')) {
            validateInput(e.target);
        }
    });


    const protocolSelect = document.getElementById('protocol'), portFields = generatorPane.querySelector('.port-fields');
    function togglePortFields() { portFields.style.display = (protocolSelect.value === 'tcp' || protocolSelect.value === 'udp') ? 'grid' : 'none'; }
    protocolSelect.addEventListener('change', togglePortFields);

    const loopCheckbox = document.getElementById('loopReplayCheckbox');
    const loopCountContainer = document.getElementById('loopCountContainer');
    loopCheckbox.addEventListener('change', () => {
        loopCountContainer.classList.toggle('hidden', !loopCheckbox.checked);
    });

    function initChart() {
        const ctx = document.getElementById('trafficChart').getContext('2d');
        if (trafficChart) trafficChart.destroy();
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Packets/sec', data: [], borderColor: '#0AF8F8', backgroundColor: '#0AF8F822', borderWidth: 1, tension: 0.4, fill: true, pointRadius: 0 }] },
            options: { scales: { y: { beginAtZero: true, grid: { color: '#0AF8F822' }, ticks: { color: '#008a8a' } }, x: { grid: { color: '#0AF8F822' }, ticks: { color: '#008a8a' } } }, plugins: { legend: { display: false } } }
        });
    }

    toggleConsoleBtn.addEventListener('click', () => {
        const isHidden = consoleWrapper.classList.toggle('hidden');
        consoleArrow.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(180deg)';
    });

    async function handleFormSubmit(e, form, endpoint, type) {
        e.preventDefault();
        validateAllInputs();
        if (form.querySelector('.invalid')) {
            alert('Please fix invalid fields (highlighted in red) before starting.');
            return;
        }

        const submitBtn = form.querySelector('button[type="submit"]');
        submitBtn.disabled = true; stopBtn.disabled = false;
        submitBtn.textContent = 'Executing...';
        statusContainer.classList.remove('hidden');
        progressBar.style.width = '0%';
        statusMessage.classList.remove('text-red-400');
        consoleOutput.textContent = ''; chartTime = 0;
        initChart();
        statusTitle.textContent = `${type} Status`;
        trafficChart.data.datasets[0].label = `${type}d Packets/sec`;
        try {
            const response = await fetch(endpoint, { method: 'POST', body: new FormData(form) });
            const result = await response.json();
            if (response.ok) { statusMessage.textContent = result.message; startStatusPolling(); }
            else { throw new Error(result.error || 'Unknown error.'); }
        } catch (error) {
            statusMessage.textContent = `Error: ${error.message}`;
            statusMessage.classList.add('text-pink-500');
            submitBtn.disabled = false; stopBtn.disabled = true;
            submitBtn.textContent = `Start ${type}`;
        }
    }
    replayerForm.addEventListener('submit', (e) => handleFormSubmit(e, replayerForm, '/replay', 'Replay'));
    generatorForm.addEventListener('submit', (e) => handleFormSubmit(e, generatorForm, '/generate', 'Generation'));

    stopBtn.addEventListener('click', async () => {
        stopBtn.disabled = true; stopBtn.textContent = 'Aborting...';
        try { await fetch('/stop', { method: 'POST' }); }
        catch (error) { statusMessage.textContent = 'Error sending stop signal.'; }
    });

    function startStatusPolling() {
        if (statusInterval) clearInterval(statusInterval);
        statusInterval = setInterval(async () => {
            try {
                const response = await fetch('/status');
                const status = await response.json();
                statusMessage.textContent = status.message;
                progressBar.style.width = `${(status.total > 0) ? (status.progress / status.total) * 100 : 0}%`;
                if (trafficChart.data.labels.length > 30) {
                    trafficChart.data.labels.shift();
                    trafficChart.data.datasets[0].data.shift();
                }
                trafficChart.data.labels.push(chartTime++);
                trafficChart.data.datasets[0].data.push(status.packets_per_second);
                trafficChart.update('quiet');
                consoleOutput.textContent = status.logs.join('\\n');
                consoleOutput.scrollTop = consoleOutput.scrollHeight;
                if (status.error) { statusMessage.classList.add('text-pink-500'); progressBar.classList.add('bg-pink-500'); stopStatusPolling(); }
                if (!status.is_running) stopStatusPolling();
            } catch (error) { statusMessage.textContent = 'Connection to backend lost.'; statusMessage.classList.add('text-pink-500'); stopStatusPolling(); }
        }, 1000);
    }

    function stopStatusPolling() {
        clearInterval(statusInterval); statusInterval = null;
        replayerForm.querySelector('button[type="submit"]').disabled = false;
        generatorForm.querySelector('button[type="submit"]').disabled = false;
        replayerForm.querySelector('button[type="submit"]').textContent = 'Initiate Replay';
        generatorForm.querySelector('button[type="submit"]').textContent = 'Generate Traffic';
        stopBtn.disabled = true; stopBtn.textContent = 'Abort';
    }

    initChart();
    switchTab('replayer');
    togglePortFields();
    fetchAssets();
    fetchConfigs();
    validateAllInputs();
});
