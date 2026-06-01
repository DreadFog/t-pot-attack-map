(function () {
    const DEFAULT_OTHER_COLOR = '#78909C';

    const state = {
        services: {
            OTHER: {
                name: 'OTHER',
                ports: [],
                color: DEFAULT_OTHER_COLOR
            }
        },
        loaded: false
    };

    function protocolKey(value) {
        return String(value || '').trim().toUpperCase();
    }

    function protocolClassName(value) {
        const key = protocolKey(value);
        const normalized = key
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '_')
            .replace(/^_+|_+$/g, '');
        return normalized || 'other';
    }

    function normalizeServices(rawServices) {
        const normalized = {};

        if (rawServices && typeof rawServices === 'object') {
            Object.entries(rawServices).forEach(([serviceName, serviceConfig]) => {
                const key = protocolKey(serviceName);
                if (!key) {
                    return;
                }

                const ports = Array.isArray(serviceConfig && serviceConfig.ports)
                    ? serviceConfig.ports.filter((port) => Number.isInteger(port))
                    : [];
                const color = typeof (serviceConfig && serviceConfig.color) === 'string' && serviceConfig.color.trim()
                    ? serviceConfig.color.trim()
                    : DEFAULT_OTHER_COLOR;

                normalized[key] = {
                    name: String(serviceName).trim() || key,
                    ports: ports,
                    color: color
                };
            });
        }

        if (!normalized.OTHER) {
            normalized.OTHER = {
                name: 'OTHER',
                ports: [],
                color: DEFAULT_OTHER_COLOR
            };
        }

        return normalized;
    }

    function isNumericProtocol(protocol) {
        return /^\d+$/.test(String(protocol || '').trim());
    }

    function normalizeProtocol(protocol) {
        if (protocol === null || protocol === undefined) {
            return 'OTHER';
        }

        const raw = String(protocol).trim();
        if (!raw || isNumericProtocol(raw)) {
            return 'OTHER';
        }

        const key = protocolKey(raw);
        return state.services[key] ? key : 'OTHER';
    }

    function getProtocolColor(protocol) {
        const normalized = normalizeProtocol(protocol);
        return (state.services[normalized] && state.services[normalized].color)
            || (state.services.OTHER && state.services.OTHER.color)
            || DEFAULT_OTHER_COLOR;
    }

    function getProtocolClass(protocol) {
        const normalized = normalizeProtocol(protocol);
        return 'protocol-' + protocolClassName(normalized);
    }

    function getProtocolLabel(protocol) {
        const normalized = normalizeProtocol(protocol);
        return (state.services[normalized] && state.services[normalized].name) || normalized;
    }

    function getKnownProtocols(options) {
        const includeOther = !options || options.includeOther !== false;
        return Object.keys(state.services).filter((protocol) => includeOther || protocol !== 'OTHER');
    }

    function cloneServices() {
        return JSON.parse(JSON.stringify(state.services));
    }

    function getContrastTextColor(hexColor) {
        const hex = String(hexColor || '').replace('#', '').trim();
        if (!/^[0-9A-Fa-f]{6}$/.test(hex)) {
            return '#000';
        }

        const r = parseInt(hex.slice(0, 2), 16);
        const g = parseInt(hex.slice(2, 4), 16);
        const b = parseInt(hex.slice(4, 6), 16);

        // WCAG relative luminance approximation for quick readable text color.
        const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
        return luminance > 0.6 ? '#000' : '#fff';
    }

    function ensureProtocolStyles() {
        let styleEl = document.getElementById('dynamic-protocol-styles');
        if (!styleEl) {
            styleEl = document.createElement('style');
            styleEl.id = 'dynamic-protocol-styles';
            document.head.appendChild(styleEl);
        }

        const rules = getKnownProtocols({ includeOther: true }).map((protocol) => {
            const className = getProtocolClass(protocol);
            const color = getProtocolColor(protocol);
            const textColor = getContrastTextColor(color);
            return '.' + className + ' { background-color: ' + color + '; color: ' + textColor + '; }';
        });

        styleEl.textContent = rules.join('\n');
    }

    function renderServiceLegend(target) {
        const container = typeof target === 'string' ? document.querySelector(target) : target;
        if (!container) {
            return;
        }

        container.innerHTML = '';

        getKnownProtocols({ includeOther: true }).forEach((protocol) => {
            const service = state.services[protocol] || { name: protocol };

            const item = document.createElement('div');
            item.className = 'service-item';

            const colorSwatch = document.createElement('div');
            colorSwatch.className = 'service-color';
            colorSwatch.style.backgroundColor = getProtocolColor(protocol);

            const label = document.createElement('span');
            label.textContent = service.name;

            item.appendChild(colorSwatch);
            item.appendChild(label);
            container.appendChild(item);
        });
    }

    async function load() {
        try {
            const response = await fetch('config/port_config.json', {
                cache: 'no-store'
            });

            if (!response.ok) {
                throw new Error('HTTP ' + response.status);
            }

            const json = await response.json();
            state.services = normalizeServices(json && json.services);
            state.loaded = true;
            console.log('[CONFIG] Loaded protocol/service config from config/port_config.json');
        } catch (error) {
            state.services = normalizeServices(state.services);
            state.loaded = false;
            console.warn('[CONFIG] Failed to load config/port_config.json, using defaults:', error);
        }

        ensureProtocolStyles();
        renderServiceLegend('#service-legend');

        return api;
    }

    const api = {
        load: load,
        isLoaded: function () { return state.loaded; },
        getServices: cloneServices,
        getKnownProtocols: getKnownProtocols,
        normalizeProtocol: normalizeProtocol,
        getProtocolColor: getProtocolColor,
        getProtocolClass: getProtocolClass,
        getProtocolLabel: getProtocolLabel,
        ensureProtocolStyles: ensureProtocolStyles,
        renderServiceLegend: renderServiceLegend
    };

    window.TPotServiceConfig = api;
    window.tpotServiceConfigReady = load();
})();
