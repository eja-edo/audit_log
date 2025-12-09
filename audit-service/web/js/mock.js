/**
 * Audit Log Service - Mock API
 * -----------------------------
 * Mock data để test UI không cần backend
 * Bật bằng CONFIG.USE_MOCK = true
 */

const MockAPI = {
    // Mock data storage
    _events: [],
    _keys: [],
    _eventIdCounter: 1,

    /**
     * Initialize mock data
     */
    init() {
        // Tạo mock keys
        this._keys = [
            {
                key_id: 'payment-service:v1234567890',
                service_id: 'payment-service',
                algorithm: 'ed25519',
                public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----',
                created_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
                revoked: false,
                metadata: { environment: 'production' }
            },
            {
                key_id: 'user-service:v9876543210',
                service_id: 'user-service',
                algorithm: 'ed25519',
                public_key_pem: '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----',
                created_at: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString(),
                revoked: false,
                metadata: { environment: 'staging' }
            }
        ];

        // Tạo mock events
        const eventTypes = ['USER_LOGIN', 'USER_LOGOUT', 'PAYMENT_CREATED', 'ORDER_PLACED', 'CONFIG_CHANGED'];
        const services = ['payment-service', 'user-service', 'order-service'];

        for (let i = 0; i < 50; i++) {
            const timestamp = new Date(Date.now() - i * 60 * 1000);
            const service = services[Math.floor(Math.random() * services.length)];
            const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
            const verified = Math.random() > 0.1;

            this._events.push({
                id: this._eventIdCounter++,
                timestamp: timestamp.toISOString(),
                service_id: service,
                event_type: eventType,
                event_canonical: JSON.stringify({
                    action: eventType.toLowerCase().replace('_', ' '),
                    user_id: `user_${1000 + i}`,
                    ip_address: `192.168.1.${100 + (i % 50)}`,
                    details: {
                        browser: 'Chrome 120',
                        os: 'Windows 11'
                    }
                }),
                event_hash: this._generateHash(),
                chain_hash: this._generateHash(),
                signature: btoa(this._generateHash()),
                public_key_id: `${service}:v1234567890`,
                verified: verified
            });
        }
    },

    /**
     * Generate random hash (mock)
     */
    _generateHash() {
        const chars = '0123456789abcdef';
        let hash = '';
        for (let i = 0; i < 64; i++) {
            hash += chars[Math.floor(Math.random() * chars.length)];
        }
        return hash;
    },

    /**
     * Simulate network delay
     */
    async _delay(ms = 300) {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    /**
     * GET /v1/logs/recent
     */
    async getRecentEvents(filters = {}) {
        await this._delay();

        let events = [...this._events];

        // Apply filters
        if (filters.service_id) {
            events = events.filter(e => e.service_id.includes(filters.service_id));
        }
        if (filters.verified !== undefined && filters.verified !== '') {
            const verifiedBool = filters.verified === 'true' || filters.verified === true;
            events = events.filter(e => e.verified === verifiedBool);
        }
        if (filters.event_type) {
            events = events.filter(e => e.event_type.includes(filters.event_type.toUpperCase()));
        }
        if (filters.search) {
            const search = filters.search.toLowerCase();
            events = events.filter(e =>
                e.event_hash.toLowerCase().includes(search) ||
                e.event_canonical.toLowerCase().includes(search)
            );
        }

        // Pagination
        const offset = filters.offset || 0;
        const limit = filters.limit || 20;
        const paginatedEvents = events.slice(offset, offset + limit);

        return {
            events: paginatedEvents,
            total: events.length,
            offset: offset,
            limit: limit
        };
    },

    /**
     * GET /v1/logs/{event_id}
     */
    async getEvent(eventId) {
        await this._delay();

        const event = this._events.find(e => e.id === parseInt(eventId));
        if (!event) {
            const error = new Error('Event not found');
            error.status = 404;
            throw error;
        }

        return event;
    },

    /**
     * POST /v1/logs
     */
    async createEvent(eventData) {
        await this._delay(500);

        const newEvent = {
            id: this._eventIdCounter++,
            timestamp: new Date().toISOString(),
            service_id: eventData.service_id,
            event_type: eventData.event_type || 'CUSTOM_EVENT',
            event_canonical: eventData.event_canonical,
            event_hash: this._generateHash(),
            chain_hash: this._generateHash(),
            signature: eventData.signature,
            public_key_id: eventData.public_key_id,
            verified: Math.random() > 0.2
        };

        this._events.unshift(newEvent);

        return {
            status: 'accepted',
            event_id: newEvent.id,
            event_hash: newEvent.event_hash
        };
    },

    /**
     * POST /v1/admin/keys
     */
    async registerKey(keyData) {
        await this._delay(500);

        const keyId = `${keyData.service_id}:v${Date.now()}`;
        const newKey = {
            key_id: keyId,
            service_id: keyData.service_id,
            algorithm: keyData.algorithm || 'ed25519',
            public_key_pem: keyData.public_key_pem,
            created_at: new Date().toISOString(),
            revoked: false,
            metadata: keyData.metadata || {}
        };

        this._keys.push(newKey);

        return {
            status: 'registered',
            key_id: keyId
        };
    },

    /**
     * GET /v1/admin/keys
     */
    async listKeys(serviceId = null) {
        await this._delay();

        let keys = [...this._keys];
        if (serviceId) {
            keys = keys.filter(k => k.service_id.includes(serviceId));
        }

        return { keys };
    },

    /**
     * DELETE /v1/admin/keys/{key_id}
     */
    async revokeKey(keyId) {
        await this._delay();

        const key = this._keys.find(k => k.key_id === keyId);
        if (key) {
            key.revoked = true;
            key.revoked_at = new Date().toISOString();
        }

        return { status: 'revoked', key_id: keyId };
    },

    /**
     * POST /v1/admin/verify
     */
    async verifySignature(eventId) {
        await this._delay(800);

        const event = this._events.find(e => e.id === parseInt(eventId));
        if (!event) {
            return { verified: false, reason: 'Event not found' };
        }

        // Mock verification - 90% success rate
        const verified = Math.random() > 0.1;
        event.verified = verified;

        return {
            verified: verified,
            event_id: eventId,
            reason: verified ? 'Signature valid' : 'Invalid signature'
        };
    },

    /**
     * POST /v1/admin/verify-chain
     */
    async verifyChain(options = {}) {
        await this._delay(1000);

        // Mock chain verification
        const chainOk = Math.random() > 0.1;
        const totalEvents = 50;
        const verifiedCount = chainOk ? totalEvents : Math.floor(Math.random() * totalEvents);

        return {
            chain_ok: chainOk,
            total_events: totalEvents,
            verified_count: verifiedCount,
            first_broken_at: chainOk ? null : verifiedCount + 1,
            details: chainOk ? 'Chain integrity verified' : `Chain broken at event ${verifiedCount + 1}`
        };
    },

    /**
     * GET /health
     */
    async healthCheck() {
        await this._delay(100);
        return {
            status: 'healthy',
            mode: 'mock',
            timestamp: new Date().toISOString()
        };
    },

    /**
     * Generate a new mock event (for live tail simulation)
     */
    generateNewEvent() {
        const eventTypes = ['USER_LOGIN', 'USER_LOGOUT', 'PAYMENT_CREATED', 'ORDER_PLACED', 'CONFIG_CHANGED'];
        const services = ['payment-service', 'user-service', 'order-service'];

        const service = services[Math.floor(Math.random() * services.length)];
        const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];

        const newEvent = {
            id: this._eventIdCounter++,
            timestamp: new Date().toISOString(),
            service_id: service,
            event_type: eventType,
            event_canonical: JSON.stringify({
                action: eventType.toLowerCase().replace('_', ' '),
                user_id: `user_${Math.floor(Math.random() * 10000)}`,
                ip_address: `192.168.1.${Math.floor(Math.random() * 255)}`
            }),
            event_hash: this._generateHash(),
            chain_hash: this._generateHash(),
            signature: btoa(this._generateHash()),
            public_key_id: `${service}:v1234567890`,
            verified: Math.random() > 0.1
        };

        this._events.unshift(newEvent);
        return newEvent;
    }
};

// Initialize mock data when loaded
MockAPI.init();
