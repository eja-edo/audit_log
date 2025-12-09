/**
 * Audit Log Service - Main Application
 * --------------------------------------
 * Điều khiển giao diện Admin Dashboard
 */

// ========== State ==========
const State = {
    currentTab: 'dashboard',
    selectedEventId: null,
    events: [],
    filters: {
        service_id: '',
        verified: '',
        event_type: '',
        search: ''
    },
    pagination: {
        offset: 0,
        limit: CONFIG.PAGE_SIZE,
        total: 0
    },
    isLoading: false,
    pollIntervalId: null,
    liveEventSource: null,
    livePollIntervalId: null
};

// ========== DOM Elements ==========
const DOM = {
    // Navigation
    navItems: null,
    tabContents: null,

    // Connection
    connectionStatus: null,
    statusDot: null,
    statusText: null,

    // Filters
    filterServiceId: null,
    filterVerified: null,
    filterEventType: null,
    searchQuery: null,
    applyFiltersBtn: null,
    clearFiltersBtn: null,
    refreshBtn: null,
    autoRefresh: null,

    // Events Table
    eventsBody: null,
    eventCount: null,
    loadMoreBtn: null,

    // Detail Panel
    detailPanel: null,
    detailContent: null,
    closeDetailBtn: null,

    // Admin Forms
    registerKeyForm: null,
    registerKeyResponse: null,
    insertEventForm: null,
    insertEventResponse: null,
    verifyChainForm: null,
    verifyChainResponse: null,
    listKeysBtn: null,
    keysList: null,

    // Live Tail
    liveFeed: null,
    livePaused: null,
    clearLiveBtn: null,
    liveStatus: null,

    // Settings Modal
    settingsModal: null,
    settingsBtn: null,
    closeSettingsBtn: null,
    cancelSettingsBtn: null,
    saveSettingsBtn: null,
    settingBaseUrl: null,
    settingAdminToken: null,
    settingPollInterval: null,
    settingUseMock: null,

    // Toast
    toastContainer: null
};

// ========== Initialization ==========
document.addEventListener('DOMContentLoaded', () => {
    initDOMReferences();
    initEventListeners();
    initSettings();
    checkConnection();
    loadEvents();

    if (CONFIG.AUTO_REFRESH_ON_START) {
        startPolling();
    }
});

/**
 * Cache DOM references
 */
function initDOMReferences() {
    // Navigation
    DOM.navItems = document.querySelectorAll('.nav-item');
    DOM.tabContents = document.querySelectorAll('.tab-content');

    // Connection
    DOM.connectionStatus = document.getElementById('connectionStatus');
    DOM.statusDot = DOM.connectionStatus.querySelector('.status-dot');
    DOM.statusText = DOM.connectionStatus.querySelector('.status-text');

    // Filters
    DOM.filterServiceId = document.getElementById('filterServiceId');
    DOM.filterVerified = document.getElementById('filterVerified');
    DOM.filterEventType = document.getElementById('filterEventType');
    DOM.searchQuery = document.getElementById('searchQuery');
    DOM.applyFiltersBtn = document.getElementById('applyFilters');
    DOM.clearFiltersBtn = document.getElementById('clearFilters');
    DOM.refreshBtn = document.getElementById('refreshBtn');
    DOM.autoRefresh = document.getElementById('autoRefresh');

    // Events Table
    DOM.eventsBody = document.getElementById('eventsBody');
    DOM.eventCount = document.getElementById('eventCount');
    DOM.loadMoreBtn = document.getElementById('loadMoreBtn');

    // Detail Panel
    DOM.detailPanel = document.getElementById('detailPanel');
    DOM.detailContent = document.getElementById('detailContent');
    DOM.closeDetailBtn = document.getElementById('closeDetailBtn');

    // Admin Forms
    DOM.registerKeyForm = document.getElementById('registerKeyForm');
    DOM.registerKeyResponse = document.getElementById('registerKeyResponse');
    DOM.insertEventForm = document.getElementById('insertEventForm');
    DOM.insertEventResponse = document.getElementById('insertEventResponse');
    DOM.verifyChainForm = document.getElementById('verifyChainForm');
    DOM.verifyChainResponse = document.getElementById('verifyChainResponse');
    DOM.listKeysBtn = document.getElementById('listKeysBtn');
    DOM.keysList = document.getElementById('keysList');
    DOM.refreshPendingBtn = document.getElementById('refreshPendingBtn');
    DOM.pendingKeysList = document.getElementById('pendingKeysList');
    DOM.listKeysStatus = document.getElementById('listKeysStatus');

    // Live Tail
    DOM.liveFeed = document.getElementById('liveFeed');
    DOM.livePaused = document.getElementById('livePaused');
    DOM.clearLiveBtn = document.getElementById('clearLiveBtn');
    DOM.liveStatus = document.getElementById('liveStatus');

    // Settings Modal
    DOM.settingsModal = document.getElementById('settingsModal');
    DOM.settingsBtn = document.getElementById('settingsBtn');
    DOM.closeSettingsBtn = document.getElementById('closeSettingsBtn');
    DOM.cancelSettingsBtn = document.getElementById('cancelSettingsBtn');
    DOM.saveSettingsBtn = document.getElementById('saveSettingsBtn');
    DOM.settingBaseUrl = document.getElementById('settingBaseUrl');
    DOM.settingAdminToken = document.getElementById('settingAdminToken');
    DOM.settingPollInterval = document.getElementById('settingPollInterval');
    DOM.settingUseMock = document.getElementById('settingUseMock');

    // Toast
    DOM.toastContainer = document.getElementById('toastContainer');
}

/**
 * Initialize event listeners
 */
function initEventListeners() {
    // Navigation
    DOM.navItems.forEach(item => {
        item.addEventListener('click', () => switchTab(item.dataset.tab));
    });

    // Filters
    DOM.applyFiltersBtn.addEventListener('click', applyFilters);
    DOM.clearFiltersBtn.addEventListener('click', clearFilters);
    DOM.refreshBtn.addEventListener('click', () => loadEvents(true));
    DOM.autoRefresh.addEventListener('change', toggleAutoRefresh);

    // Search on Enter
    DOM.searchQuery.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') applyFilters();
    });

    // Load More
    DOM.loadMoreBtn.addEventListener('click', loadMoreEvents);

    // Detail Panel
    DOM.closeDetailBtn.addEventListener('click', closeDetailPanel);

    // Admin Forms
    DOM.registerKeyForm.addEventListener('submit', handleRegisterKey);
    DOM.insertEventForm.addEventListener('submit', handleInsertEvent);
    DOM.verifyChainForm.addEventListener('submit', handleVerifyChain);
    DOM.listKeysBtn.addEventListener('click', handleListKeys);
    DOM.refreshPendingBtn.addEventListener('click', handleLoadPendingKeys);

    // Live Tail
    DOM.clearLiveBtn.addEventListener('click', clearLiveFeed);

    // Settings Modal
    DOM.settingsBtn.addEventListener('click', openSettingsModal);
    DOM.closeSettingsBtn.addEventListener('click', closeSettingsModal);
    DOM.cancelSettingsBtn.addEventListener('click', closeSettingsModal);
    DOM.saveSettingsBtn.addEventListener('click', saveSettingsFromModal);

    // Close modal on outside click
    DOM.settingsModal.addEventListener('click', (e) => {
        if (e.target === DOM.settingsModal) closeSettingsModal();
    });
}

/**
 * Initialize settings values in modal
 */
function initSettings() {
    DOM.settingBaseUrl.value = CONFIG.BASE_URL;
    DOM.settingAdminToken.value = CONFIG.ADMIN_TOKEN;
    DOM.settingPollInterval.value = CONFIG.POLL_INTERVAL / 1000;
    DOM.settingUseMock.checked = CONFIG.USE_MOCK;
}

// ========== Navigation ==========
function switchTab(tabId) {
    // Update nav
    DOM.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.tab === tabId);
    });

    // Update content
    DOM.tabContents.forEach(content => {
        content.classList.toggle('active', content.id === `${tabId}-tab`);
    });

    State.currentTab = tabId;

    // Handle live tail
    if (tabId === 'live') {
        startLiveTail();
    } else {
        stopLiveTail();
    }
}

// ========== Connection Check ==========
async function checkConnection() {
    try {
        await API.healthCheck();
        DOM.statusDot.className = 'status-dot connected';
        DOM.statusText.textContent = CONFIG.USE_MOCK ? 'Mock Mode' : 'Connected';
    } catch (error) {
        DOM.statusDot.className = 'status-dot error';
        DOM.statusText.textContent = 'Disconnected';
    }
}

// ========== Events Loading ==========
async function loadEvents(refresh = false) {
    if (State.isLoading) return;
    State.isLoading = true;

    if (refresh) {
        State.pagination.offset = 0;
        State.events = [];
    }

    try {
        const response = await API.getRecentEvents({
            ...State.filters,
            limit: State.pagination.limit,
            offset: State.pagination.offset
        });

        if (refresh) {
            State.events = response.events || [];
        } else {
            State.events = [...State.events, ...(response.events || [])];
        }

        State.pagination.total = response.total || State.events.length;

        renderEventsTable();
        updateEventCount();

        // Check connection
        DOM.statusDot.className = 'status-dot connected';
        DOM.statusText.textContent = CONFIG.USE_MOCK ? 'Mock Mode' : 'Connected';

    } catch (error) {
        console.error('Failed to load events:', error);
        showToast('error', `Failed to load events: ${error.message}`);
        DOM.statusDot.className = 'status-dot error';
        DOM.statusText.textContent = 'Error';
    } finally {
        State.isLoading = false;
    }
}

async function loadMoreEvents() {
    State.pagination.offset += State.pagination.limit;
    await loadEvents(false);
}

function renderEventsTable() {
    DOM.eventsBody.innerHTML = '';

    if (State.events.length === 0) {
        DOM.eventsBody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center text-muted" style="padding: 40px;">
                    No events found
                </td>
            </tr>
        `;
        return;
    }

    State.events.forEach(event => {
        const row = document.createElement('tr');
        row.dataset.eventId = event.id;

        if (event.id === State.selectedEventId) {
            row.classList.add('selected');
        }

        row.innerHTML = `
            <td>${event.id}</td>
            <td>${formatTimestamp(event.timestamp)}</td>
            <td>${escapeHtml(event.service_id)}</td>
            <td>${escapeHtml(event.event_type || '-')}</td>
            <td class="hash-preview" title="${event.event_hash}">${event.event_hash?.substring(0, 16) || '-'}...</td>
            <td>
                <span class="status-badge ${event.verified ? 'verified' : 'not-verified'}">
                    ${event.verified ? '✓ Verified' : '✗ Not Verified'}
                </span>
            </td>
        `;

        row.addEventListener('click', () => selectEvent(event.id));
        DOM.eventsBody.appendChild(row);
    });

    // Show/hide load more button
    DOM.loadMoreBtn.style.display =
        State.events.length < State.pagination.total ? 'inline-block' : 'none';
}

function updateEventCount() {
    DOM.eventCount.textContent = `${State.events.length} of ${State.pagination.total} events`;
}

// ========== Filters ==========
function applyFilters() {
    State.filters = {
        service_id: DOM.filterServiceId.value.trim(),
        verified: DOM.filterVerified.value,
        event_type: DOM.filterEventType.value.trim(),
        search: DOM.searchQuery.value.trim()
    };

    loadEvents(true);
}

function clearFilters() {
    DOM.filterServiceId.value = '';
    DOM.filterVerified.value = '';
    DOM.filterEventType.value = '';
    DOM.searchQuery.value = '';

    State.filters = {
        service_id: '',
        verified: '',
        event_type: '',
        search: ''
    };

    loadEvents(true);
}

// ========== Auto Refresh / Polling ==========
function toggleAutoRefresh() {
    if (DOM.autoRefresh.checked) {
        startPolling();
    } else {
        stopPolling();
    }
}

function startPolling() {
    stopPolling();
    State.pollIntervalId = setInterval(() => {
        if (State.currentTab === 'dashboard' && !State.isLoading) {
            loadEvents(true);
        }
    }, CONFIG.POLL_INTERVAL);
}

function stopPolling() {
    if (State.pollIntervalId) {
        clearInterval(State.pollIntervalId);
        State.pollIntervalId = null;
    }
}

// ========== Event Detail ==========
async function selectEvent(eventId) {
    State.selectedEventId = eventId;

    // Update table selection
    document.querySelectorAll('.events-table tbody tr').forEach(row => {
        row.classList.toggle('selected', parseInt(row.dataset.eventId) === eventId);
    });

    // Find event in state
    let event = State.events.find(e => e.id === eventId);

    if (!event) {
        try {
            event = await API.getEvent(eventId);
        } catch (error) {
            showToast('error', `Failed to load event: ${error.message}`);
            return;
        }
    }

    renderEventDetail(event);
}

function renderEventDetail(event) {
    // Parse canonical JSON
    let canonicalData;
    try {
        canonicalData = typeof event.event_canonical === 'string'
            ? JSON.parse(event.event_canonical)
            : event.event_canonical;
    } catch {
        canonicalData = event.event_canonical;
    }

    // Parse event_data
    let eventData = {};
    try {
        eventData = typeof event.event_data === 'string'
            ? JSON.parse(event.event_data)
            : event.event_data;
    } catch {
        eventData = event.event_data;
    }

    DOM.detailContent.innerHTML = `
        <div class="detail-section">
            <h4>📌 Basic Info</h4>
            <div class="detail-row">
                <span class="label">Event ID</span>
                <span class="value">${event.id}</span>
            </div>
            <div class="detail-row">
                <span class="label">Timestamp</span>
                <span class="value">${formatTimestamp(event.timestamp, true)}</span>
            </div>
            <div class="detail-row">
                <span class="label">Service</span>
                <span class="value">${escapeHtml(event.service_id)}</span>
            </div>
            <div class="detail-row">
                <span class="label">Event Type</span>
                <span class="value">${escapeHtml(event.event_type || '-')}</span>
            </div>
            <div class="detail-row">
                <span class="label">Status</span>
                <span class="value">
                    <span class="status-badge ${event.verified ? 'verified' : 'not-verified'}">
                        ${event.verified ? '✓ Verified' : '✗ Not Verified'}
                    </span>
                </span>
            </div>
            <div class="detail-row">
                <span class="label">Public Key ID</span>
                <span class="value value-small">${event.public_key_id || '-'}</span>
            </div>
        </div>
        
        <div class="detail-section">
            <h4>📦 Event Data</h4>
            <div class="json-viewer json-viewer-large">${formatJSON(eventData)}</div>
        </div>
        
        <div class="detail-section">
            <h4>🔗 Hashes</h4>
            <div class="hash-box">
                <div class="hash-item">
                    <span class="hash-label">Event Hash</span>
                    <span class="hash-value">${event.event_hash || '-'}</span>
                </div>
                <div class="hash-item">
                    <span class="hash-label">Chain Hash</span>
                    <span class="hash-value">${event.chain_hash || '-'}</span>
                </div>
            </div>
        </div>
        
        <div class="detail-section collapsible">
            <h4 class="collapsible-header" onclick="toggleCollapsible(this)">
                📝 Event Canonical (JSON) <span class="collapse-icon">▶</span>
            </h4>
            <div class="collapsible-content collapsed">
                <div class="json-viewer">${formatJSON(canonicalData)}</div>
            </div>
        </div>
        
        <div class="detail-section collapsible">
            <h4 class="collapsible-header" onclick="toggleCollapsible(this)">
                🔐 Signature (Base64) <span class="collapse-icon">▶</span>
            </h4>
            <div class="collapsible-content collapsed">
                <div class="signature-box">${event.signature || '-'}</div>
            </div>
        </div>
        
        <div class="detail-actions">
            <button class="btn btn-primary" onclick="verifyEventSignature(${event.id})">
                🔐 Verify Signature
            </button>
            <button class="btn btn-secondary" onclick="copyEventHash('${event.event_hash}')">
                📋 Copy Hash
            </button>
        </div>
        
        <div class="response-box" id="verifyEventResponse"></div>
    `;
}

function closeDetailPanel() {
    State.selectedEventId = null;
    document.querySelectorAll('.events-table tbody tr').forEach(row => {
        row.classList.remove('selected');
    });

    DOM.detailContent.innerHTML = `
        <div class="empty-state">
            <span class="empty-icon">📋</span>
            <p>Select an event to view details</p>
        </div>
    `;
}

async function verifyEventSignature(eventId) {
    const responseBox = document.getElementById('verifyEventResponse');
    responseBox.className = 'response-box visible';

    // Note: Single event signature verification is done automatically during ingestion
    // This button shows the current verification status
    const event = State.events.find(e => e.id === eventId);

    if (event) {
        responseBox.className = `response-box visible ${event.verified ? 'success' : 'error'}`;
        responseBox.textContent = JSON.stringify({
            event_id: eventId,
            verified: event.verified,
            message: event.verified
                ? 'Signature was verified during ingestion'
                : 'Signature verification failed during ingestion'
        }, null, 2);

        showToast(event.verified ? 'success' : 'warning',
            event.verified ? 'Signature was verified!' : 'Signature verification failed');
    } else {
        responseBox.className = 'response-box visible error';
        responseBox.textContent = 'Event not found in current state';
        showToast('error', 'Event not found');
    }
}

function copyEventHash(hash) {
    navigator.clipboard.writeText(hash).then(() => {
        showToast('success', 'Hash copied to clipboard!');
    }).catch(() => {
        showToast('error', 'Failed to copy hash');
    });
}

function toggleCollapsible(header) {
    const content = header.nextElementSibling;
    const icon = header.querySelector('.collapse-icon');

    if (content.classList.contains('collapsed')) {
        content.classList.remove('collapsed');
        icon.textContent = '▼';
    } else {
        content.classList.add('collapsed');
        icon.textContent = '▶';
    }
}

// ========== Admin: Register Key ==========
async function handleRegisterKey(e) {
    e.preventDefault();

    const serviceId = document.getElementById('keyServiceId').value.trim();
    const algorithm = document.getElementById('keyAlgorithm').value;
    const publicKeyPem = document.getElementById('publicKeyPem').value.trim();
    const metadataStr = document.getElementById('keyMetadata').value.trim();

    let metadata = {};
    if (metadataStr) {
        try {
            metadata = JSON.parse(metadataStr);
        } catch {
            showToast('error', 'Invalid JSON in metadata');
            return;
        }
    }

    DOM.registerKeyResponse.className = 'response-box visible';
    DOM.registerKeyResponse.textContent = 'Registering key...';

    try {
        const result = await API.registerKey({
            service_id: serviceId,
            algorithm: algorithm,
            public_key_pem: publicKeyPem,
            metadata: metadata
        });

        DOM.registerKeyResponse.className = 'response-box visible success';
        DOM.registerKeyResponse.textContent = JSON.stringify(result, null, 2);
        showToast('success', 'Key registered successfully!');

        // Clear form
        DOM.registerKeyForm.reset();

    } catch (error) {
        DOM.registerKeyResponse.className = 'response-box visible error';
        DOM.registerKeyResponse.textContent = `Error: ${error.message}\n\n${JSON.stringify(error.data, null, 2)}`;
        showToast('error', error.message);
    }
}

// ========== Admin: Insert Event ==========
async function handleInsertEvent(e) {
    e.preventDefault();

    const serviceId = document.getElementById('eventServiceId').value.trim();
    const eventType = document.getElementById('eventType').value.trim();
    const eventCanonical = document.getElementById('eventCanonical').value.trim();
    const signature = document.getElementById('eventSignature').value.trim();
    const publicKeyId = document.getElementById('eventPublicKeyId').value.trim();

    // Validate JSON
    try {
        JSON.parse(eventCanonical);
    } catch {
        showToast('error', 'Invalid JSON in event canonical');
        return;
    }

    DOM.insertEventResponse.className = 'response-box visible';
    DOM.insertEventResponse.textContent = 'Submitting event...';

    try {
        const result = await API.createEvent({
            service_id: serviceId,
            event_type: eventType,
            event_canonical: eventCanonical,
            signature: signature,
            public_key_id: publicKeyId
        });

        DOM.insertEventResponse.className = 'response-box visible success';
        DOM.insertEventResponse.textContent = JSON.stringify(result, null, 2);
        showToast('success', 'Event submitted successfully!');

        // Refresh events list
        loadEvents(true);

    } catch (error) {
        DOM.insertEventResponse.className = 'response-box visible error';
        DOM.insertEventResponse.textContent = `Error: ${error.message}\n\n${JSON.stringify(error.data, null, 2)}`;
        showToast('error', error.message);
    }
}

// ========== Admin: Verify Chain ==========
async function handleVerifyChain(e) {
    e.preventDefault();

    const serviceId = document.getElementById('chainServiceId').value.trim();

    if (!serviceId) {
        showToast('error', 'Service ID is required');
        return;
    }

    DOM.verifyChainResponse.className = 'response-box visible';
    DOM.verifyChainResponse.textContent = 'Verifying chain...';

    try {
        const result = await API.verifyChain(serviceId);

        DOM.verifyChainResponse.className = `response-box visible ${result.is_valid ? 'success' : 'error'}`;
        DOM.verifyChainResponse.textContent = JSON.stringify(result, null, 2);

        showToast(result.is_valid ? 'success' : 'warning',
            result.is_valid ? `Chain integrity verified! (${result.events_checked} events)` : 'Chain integrity broken!');

    } catch (error) {
        DOM.verifyChainResponse.className = 'response-box visible error';
        DOM.verifyChainResponse.textContent = `Error: ${error.message}`;
        showToast('error', error.message);
    }
}

// ========== Admin: Pending Key Approvals ==========
async function handleLoadPendingKeys() {
    DOM.pendingKeysList.innerHTML = '<div class="text-muted">Loading...</div>';

    try {
        const result = await API.getPendingKeys();
        const keys = result.keys || [];

        if (keys.length === 0) {
            DOM.pendingKeysList.innerHTML = `
                <div class="empty-state">
                    <span class="empty-icon">✅</span>
                    <p>No pending key requests</p>
                </div>
            `;
            return;
        }

        DOM.pendingKeysList.innerHTML = keys.map(key => `
            <div class="pending-key-item">
                <div class="key-info">
                    <div class="key-id">${escapeHtml(key.public_key_id)}</div>
                    <div class="key-meta">
                        Service: <strong>${escapeHtml(key.service_id)}</strong> | 
                        Algorithm: ${key.algorithm} | 
                        Requested: ${formatTimestamp(key.created_at, true)}
                    </div>
                    <div class="key-pem-preview">
                        <code>${escapeHtml(key.public_key_pem?.substring(0, 80))}...</code>
                    </div>
                </div>
                <div class="key-actions">
                    <button class="btn btn-success btn-small" onclick="approveKey('${key.public_key_id}')">
                        ✅ Approve
                    </button>
                    <button class="btn btn-danger btn-small" onclick="rejectKey('${key.public_key_id}')">
                        ❌ Reject
                    </button>
                </div>
            </div>
        `).join('');

        showToast('info', `${keys.length} pending key(s) found`);

    } catch (error) {
        DOM.pendingKeysList.innerHTML = `<div class="text-danger">Error: ${error.message}</div>`;
        showToast('error', error.message);
    }
}

async function approveKey(keyId) {
    if (!confirm(`Approve key "${keyId}"?\n\nThis will allow the service to submit signed events.`)) {
        return;
    }

    try {
        await API.reviewKey(keyId, 'approve');
        showToast('success', `Key approved: ${keyId}`);
        handleLoadPendingKeys();
        handleListKeys();
    } catch (error) {
        showToast('error', error.message);
    }
}

async function rejectKey(keyId) {
    const reason = prompt(`Reject key "${keyId}"?\n\nPlease provide a reason:`);

    if (reason === null) return; // Cancelled

    if (!reason.trim()) {
        showToast('error', 'Rejection reason is required');
        return;
    }

    try {
        await API.reviewKey(keyId, 'reject', reason);
        showToast('warning', `Key rejected: ${keyId}`);
        handleLoadPendingKeys();
    } catch (error) {
        showToast('error', error.message);
    }
}

// ========== Admin: List Keys ==========
async function handleListKeys() {
    const serviceId = document.getElementById('listKeysServiceId').value.trim();
    const status = DOM.listKeysStatus?.value || null;

    DOM.keysList.innerHTML = '<div class="text-muted">Loading...</div>';

    try {
        const result = await API.listKeys(serviceId || null, status || null);
        const keys = result.keys || [];

        if (keys.length === 0) {
            DOM.keysList.innerHTML = '<div class="text-muted">No keys found</div>';
            return;
        }

        DOM.keysList.innerHTML = keys.map(key => {
            const isDisabled = key.disabled_at !== null;
            const keyId = key.public_key_id || key.key_id;
            const statusBadge = getStatusBadge(key.status, isDisabled);

            return `
                <div class="key-item ${isDisabled ? 'disabled' : ''} ${key.status === 'rejected' ? 'rejected' : ''}">
                    <div class="key-info">
                        <div class="key-id">${escapeHtml(keyId)} ${statusBadge}</div>
                        <div class="key-meta">
                            Service: ${escapeHtml(key.service_id)} | ${key.algorithm} | Created: ${formatTimestamp(key.created_at)}
                            ${key.reviewed_by ? ` | Reviewed by: ${key.reviewed_by} at ${formatTimestamp(key.reviewed_at)}` : ''}
                            ${key.rejection_reason ? ` | Reason: ${escapeHtml(key.rejection_reason)}` : ''}
                            ${key.rotated_to ? ` | Rotated to: ${key.rotated_to}` : ''}
                        </div>
                    </div>
                    <div class="key-actions">
                        ${key.status === 'approved' && !isDisabled ?
                    `<button class="btn btn-danger btn-small" onclick="disableKey('${keyId}')">Disable</button>`
                    : ''}
                    </div>
                </div>
            `;
        }).join('');

    } catch (error) {
        DOM.keysList.innerHTML = `<div class="text-danger">Error: ${error.message}</div>`;
        showToast('error', error.message);
    }
}

function getStatusBadge(status, isDisabled) {
    if (isDisabled) return '<span class="status-badge disabled">DISABLED</span>';
    switch (status) {
        case 'approved': return '<span class="status-badge approved">✅ APPROVED</span>';
        case 'pending': return '<span class="status-badge pending">⏳ PENDING</span>';
        case 'rejected': return '<span class="status-badge rejected">❌ REJECTED</span>';
        default: return '';
    }
}

async function disableKey(keyId) {
    if (!confirm(`Are you sure you want to disable key "${keyId}"?`)) {
        return;
    }

    try {
        await API.disableKey(keyId);
        showToast('success', 'Key disabled successfully');
        handleListKeys();
    } catch (error) {
        showToast('error', error.message);
    }
}

// ========== Live Tail ==========
function startLiveTail() {
    DOM.liveStatus.textContent = '🟢 Connecting...';

    // Try SSE first if enabled
    if (CONFIG.USE_SSE) {
        try {
            const eventSource = new EventSource(`${CONFIG.BASE_URL}${CONFIG.SSE_ENDPOINT}`);

            eventSource.onopen = () => {
                DOM.liveStatus.textContent = '🟢 Connected (SSE)';
            };

            eventSource.onmessage = (e) => {
                if (!DOM.livePaused.checked) {
                    const event = JSON.parse(e.data);
                    addLiveEvent(event);
                }
            };

            eventSource.onerror = () => {
                eventSource.close();
                fallbackToPolling();
            };

            State.liveEventSource = eventSource;
            return;
        } catch {
            fallbackToPolling();
        }
    } else {
        fallbackToPolling();
    }
}

function fallbackToPolling() {
    DOM.liveStatus.textContent = '🟡 Polling...';

    State.livePollIntervalId = setInterval(() => {
        if (!DOM.livePaused.checked) {
            if (CONFIG.USE_MOCK) {
                // Generate mock event
                const event = MockAPI.generateNewEvent();
                addLiveEvent(event);
            } else {
                // Poll for new events
                pollNewEvents();
            }
        }
    }, CONFIG.POLL_INTERVAL);
}

let lastEventId = null;

async function pollNewEvents() {
    try {
        const response = await API.getRecentEvents({ limit: 5 });
        const events = response.events || [];

        events.forEach(event => {
            if (!lastEventId || event.id > lastEventId) {
                addLiveEvent(event);
            }
        });

        if (events.length > 0) {
            lastEventId = events[0].id;
        }
    } catch (error) {
        console.error('Poll error:', error);
    }
}

function addLiveEvent(event) {
    // Remove empty state
    const emptyState = DOM.liveFeed.querySelector('.empty-state');
    if (emptyState) {
        emptyState.remove();
    }

    const eventEl = document.createElement('div');
    eventEl.className = `live-event ${event.verified ? 'verified' : 'not-verified'}`;
    eventEl.innerHTML = `
        <div class="live-event-header">
            <span>${formatTimestamp(event.timestamp, true)}</span>
            <span>${event.service_id} | ${event.event_type || 'EVENT'}</span>
        </div>
        <div class="live-event-body">
            ${escapeHtml(event.event_hash?.substring(0, 32))}... | 
            ${event.verified ? '✓ Verified' : '✗ Not Verified'}
        </div>
    `;

    DOM.liveFeed.insertBefore(eventEl, DOM.liveFeed.firstChild);

    // Limit displayed events
    const events = DOM.liveFeed.querySelectorAll('.live-event');
    if (events.length > CONFIG.MAX_LIVE_EVENTS) {
        events[events.length - 1].remove();
    }
}

function stopLiveTail() {
    if (State.liveEventSource) {
        State.liveEventSource.close();
        State.liveEventSource = null;
    }

    if (State.livePollIntervalId) {
        clearInterval(State.livePollIntervalId);
        State.livePollIntervalId = null;
    }

    DOM.liveStatus.textContent = '⚪ Disconnected';
}

function clearLiveFeed() {
    DOM.liveFeed.innerHTML = `
        <div class="empty-state">
            <span class="empty-icon">📡</span>
            <p>Waiting for events...</p>
            <p class="hint">Events will appear here in real-time</p>
        </div>
    `;
}

// ========== Settings Modal ==========
function openSettingsModal() {
    DOM.settingBaseUrl.value = CONFIG.BASE_URL;
    DOM.settingAdminToken.value = CONFIG.ADMIN_TOKEN;
    DOM.settingPollInterval.value = CONFIG.POLL_INTERVAL / 1000;
    DOM.settingUseMock.checked = CONFIG.USE_MOCK;

    DOM.settingsModal.classList.add('visible');
}

function closeSettingsModal() {
    DOM.settingsModal.classList.remove('visible');
}

function saveSettingsFromModal() {
    const settings = {
        baseUrl: DOM.settingBaseUrl.value.trim(),
        adminToken: DOM.settingAdminToken.value.trim(),
        pollInterval: parseInt(DOM.settingPollInterval.value) || 5,
        useMock: DOM.settingUseMock.checked
    };

    saveSettings(settings);

    // Restart polling with new interval
    if (DOM.autoRefresh.checked) {
        startPolling();
    }

    // Check connection with new settings
    checkConnection();

    closeSettingsModal();
    showToast('success', 'Settings saved!');

    // Reload events with new settings
    loadEvents(true);
}

// ========== Toast Notifications ==========
function showToast(type, message) {
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type]}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
        <span class="toast-close" onclick="this.parentElement.remove()">✕</span>
    `;

    DOM.toastContainer.appendChild(toast);

    // Auto remove
    setTimeout(() => {
        if (toast.parentElement) {
            toast.remove();
        }
    }, CONFIG.TOAST_DURATION);
}

// ========== Utility Functions ==========
function formatTimestamp(timestamp, full = false) {
    if (!timestamp) return '-';

    const date = new Date(timestamp);
    if (full) {
        return date.toLocaleString('vi-VN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    return date.toLocaleString('vi-VN', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatJSON(data) {
    if (!data) return '';

    const json = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

    // Syntax highlighting
    return json
        .replace(/(".*?")\s*:/g, '<span class="json-key">$1</span>:')
        .replace(/:\s*(".*?")/g, ': <span class="json-string">$1</span>')
        .replace(/:\s*(\d+)/g, ': <span class="json-number">$1</span>')
        .replace(/:\s*(true|false)/g, ': <span class="json-boolean">$1</span>')
        .replace(/:\s*(null)/g, ': <span class="json-null">$1</span>');
}
