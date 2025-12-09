/**
 * Audit Log Service - Configuration
 * ----------------------------------
 * Cấu hình cho Admin Dashboard
 */

const CONFIG = {
    // ========== API Configuration ==========
    // Base URL của Audit Log API
    BASE_URL: 'http://localhost',

    // Admin Token để gọi các endpoint admin
    ADMIN_TOKEN: 'my-super-secret-admin-token-2025',

    // ========== Polling Configuration ==========
    // Khoảng thời gian polling (ms) - 5 giây mặc định
    POLL_INTERVAL: 5000,

    // Số event load mỗi lần
    PAGE_SIZE: 20,

    // ========== Mock Mode ==========
    // Bật mode mock để test UI không cần backend
    USE_MOCK: false,

    // ========== Live Tail Configuration ==========
    // Sử dụng SSE nếu server hỗ trợ, nếu không sẽ fallback sang polling
    USE_SSE: false,
    SSE_ENDPOINT: '/v1/events/stream',

    // Max events hiển thị trong live tail
    MAX_LIVE_EVENTS: 100,

    // ========== UI Configuration ==========
    // Tự động refresh khi khởi động
    AUTO_REFRESH_ON_START: true,

    // Thời gian toast hiển thị (ms)
    TOAST_DURATION: 4000,

    // ========== Local Storage Keys ==========
    STORAGE_KEYS: {
        SETTINGS: 'audit_dashboard_settings',
        FILTERS: 'audit_dashboard_filters'
    }
};

/**
 * Load settings từ localStorage
 */
function loadSettings() {
    try {
        const saved = localStorage.getItem(CONFIG.STORAGE_KEYS.SETTINGS);
        if (saved) {
            const settings = JSON.parse(saved);
            CONFIG.BASE_URL = settings.baseUrl || CONFIG.BASE_URL;
            CONFIG.ADMIN_TOKEN = settings.adminToken || CONFIG.ADMIN_TOKEN;
            CONFIG.POLL_INTERVAL = (settings.pollInterval || 5) * 1000;
            CONFIG.USE_MOCK = settings.useMock || false;
        }
    } catch (e) {
        console.warn('Failed to load settings:', e);
    }
}

/**
 * Save settings vào localStorage
 */
function saveSettings(settings) {
    try {
        localStorage.setItem(CONFIG.STORAGE_KEYS.SETTINGS, JSON.stringify(settings));
        CONFIG.BASE_URL = settings.baseUrl;
        CONFIG.ADMIN_TOKEN = settings.adminToken;
        CONFIG.POLL_INTERVAL = settings.pollInterval * 1000;
        CONFIG.USE_MOCK = settings.useMock;
    } catch (e) {
        console.warn('Failed to save settings:', e);
    }
}

// Load settings khi khởi động
loadSettings();
