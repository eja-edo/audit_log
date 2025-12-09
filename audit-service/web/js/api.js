/**
 * Audit Log Service - API Client
 * --------------------------------
 * Module gọi API đến Audit Log Service
 */

const API = {
    /**
     * Helper: Tạo headers cho request
     */
    getHeaders(includeAuth = false) {
        const headers = {
            'Content-Type': 'application/json'
        };
        if (includeAuth && CONFIG.ADMIN_TOKEN) {
            headers['X-Admin-Token'] = CONFIG.ADMIN_TOKEN;
        }
        return headers;
    },

    /**
     * Helper: Xử lý response từ API
     */
    async handleResponse(response) {
        const contentType = response.headers.get('content-type');
        let data;

        if (contentType && contentType.includes('application/json')) {
            data = await response.json();
        } else {
            data = await response.text();
        }

        if (!response.ok) {
            const error = new Error(data.detail || data.message || 'API Error');
            error.status = response.status;
            error.data = data;
            throw error;
        }

        return data;
    },

    /**
     * GET /v1/logs - Lấy danh sách events với filters
     * @param {Object} filters - Filters: service_id, verified, event_type, limit, offset
     */
    async getRecentEvents(filters = {}) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.getRecentEvents(filters);
        }

        const params = new URLSearchParams();
        if (filters.service_id) params.append('service_id', filters.service_id);
        if (filters.event_type) params.append('event_type', filters.event_type);
        if (filters.limit) params.append('limit', filters.limit);
        if (filters.offset) params.append('offset', filters.offset);

        const url = `${CONFIG.BASE_URL}/v1/logs?${params.toString()}`;
        const response = await fetch(url, {
            method: 'GET',
            headers: this.getHeaders()
        });

        return this.handleResponse(response);
    },

    /**
     * GET /v1/logs/{event_id} - Lấy chi tiết một event
     * @param {string} eventId - Event ID
     */
    async getEvent(eventId) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.getEvent(eventId);
        }

        const url = `${CONFIG.BASE_URL}/v1/logs/${eventId}`;
        const response = await fetch(url, {
            method: 'GET',
            headers: this.getHeaders()
        });

        return this.handleResponse(response);
    },

    /**
     * POST /v1/logs - Tạo mới event
     * @param {Object} eventData - Event data: service_id, event_type, event_canonical, signature, public_key_id
     */
    async createEvent(eventData) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.createEvent(eventData);
        }

        const url = `${CONFIG.BASE_URL}/v1/logs`;
        const response = await fetch(url, {
            method: 'POST',
            headers: this.getHeaders(),
            body: JSON.stringify(eventData)
        });

        return this.handleResponse(response);
    },

    /**
     * POST /v1/keys/register - Service tự đăng ký public key (không cần admin token)
     * @param {Object} keyData - Key data: service_id, algorithm, public_key_pem, metadata
     */
    async registerKey(keyData) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.registerKey(keyData);
        }

        const url = `${CONFIG.BASE_URL}/v1/keys/register`;
        const response = await fetch(url, {
            method: 'POST',
            headers: this.getHeaders(false),  // Không cần admin token
            body: JSON.stringify(keyData)
        });

        return this.handleResponse(response);
    },

    /**
     * GET /v1/admin/keys/pending - Lấy danh sách keys đang chờ duyệt
     */
    async getPendingKeys() {
        if (CONFIG.USE_MOCK) {
            return MockAPI.getPendingKeys();
        }

        const url = `${CONFIG.BASE_URL}/v1/admin/keys/pending`;
        const response = await fetch(url, {
            method: 'GET',
            headers: this.getHeaders(true)
        });

        return this.handleResponse(response);
    },

    /**
     * POST /v1/admin/keys/review - Approve hoặc reject key
     * @param {string} publicKeyId - ID của key
     * @param {string} action - 'approve' hoặc 'reject'
     * @param {string} reason - Lý do (bắt buộc nếu reject)
     */
    async reviewKey(publicKeyId, action, reason = null) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.reviewKey(publicKeyId, action);
        }

        const url = `${CONFIG.BASE_URL}/v1/admin/keys/review`;
        const body = {
            public_key_id: publicKeyId,
            action: action
        };
        if (reason) body.reason = reason;

        const response = await fetch(url, {
            method: 'POST',
            headers: this.getHeaders(true),
            body: JSON.stringify(body)
        });

        return this.handleResponse(response);
    },

    /**
     * GET /v1/admin/keys - Lấy danh sách public keys
     * @param {string} serviceId - Filter theo service_id (optional)
     * @param {string} status - Filter theo status: pending, approved, rejected
     */
    async listKeys(serviceId = null, status = null) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.listKeys(serviceId);
        }

        const params = new URLSearchParams();
        if (serviceId) params.append('service_id', serviceId);
        if (status) params.append('status', status);

        const url = `${CONFIG.BASE_URL}/v1/admin/keys?${params.toString()}`;
        const response = await fetch(url, {
            method: 'GET',
            headers: this.getHeaders(true)
        });

        return this.handleResponse(response);
    },

    /**
     * DELETE /v1/admin/keys/{key_id} - Disable một key
     * @param {string} keyId - Key ID
     */
    async disableKey(keyId) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.revokeKey(keyId);
        }

        const url = `${CONFIG.BASE_URL}/v1/admin/keys/${encodeURIComponent(keyId)}`;
        const response = await fetch(url, {
            method: 'DELETE',
            headers: this.getHeaders(true)
        });

        return this.handleResponse(response);
    },

    /**
     * POST /v1/admin/verify-chain - Verify chain integrity
     * @param {string} serviceId - Service ID to verify
     * @param {number} limit - Max events to check
     */
    async verifyChain(serviceId, limit = 10000) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.verifyChain({ service_id: serviceId });
        }

        const params = new URLSearchParams();
        params.append('service_id', serviceId);
        params.append('limit', limit.toString());

        const url = `${CONFIG.BASE_URL}/v1/admin/verify-chain?${params.toString()}`;
        const response = await fetch(url, {
            method: 'POST',
            headers: this.getHeaders(true)
        });

        return this.handleResponse(response);
    },

    /**
     * GET /health - Health check
     */
    async healthCheck() {
        if (CONFIG.USE_MOCK) {
            return MockAPI.healthCheck();
        }

        const url = `${CONFIG.BASE_URL}/health`;
        const response = await fetch(url, {
            method: 'GET',
            headers: this.getHeaders()
        });

        return this.handleResponse(response);
    },

    /**
     * GET /v1/admin/stats - Get service statistics
     */
    async getStats() {
        if (CONFIG.USE_MOCK) {
            return MockAPI.getStats();
        }

        const url = `${CONFIG.BASE_URL}/v1/admin/stats`;
        const response = await fetch(url, {
            method: 'GET',
            headers: this.getHeaders(true)
        });

        return this.handleResponse(response);
    },

    /**
     * POST /v1/logs/search - Full-text search
     * @param {string} searchText - Text to search
     * @param {Object} options - Additional filters: service_id, limit
     */
    async searchEvents(searchText, options = {}) {
        if (CONFIG.USE_MOCK) {
            return MockAPI.getRecentEvents({ search: searchText, ...options });
        }

        const params = new URLSearchParams();
        params.append('search_text', searchText);
        if (options.service_id) params.append('service_id', options.service_id);
        if (options.limit) params.append('limit', options.limit.toString());

        const url = `${CONFIG.BASE_URL}/v1/logs/search?${params.toString()}`;
        const response = await fetch(url, {
            method: 'POST',
            headers: this.getHeaders()
        });

        return this.handleResponse(response);
    }
};
