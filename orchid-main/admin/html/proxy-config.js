// Конфигурация прокси для обхода CORS
const PROXY_CONFIG = {
    // Режим работы: 'direct' - напрямую, 'proxy' - через прокси, 'auto' - автоматический выбор
    mode: 'auto',
    
    // Базовый URL для прокси
    proxyBaseUrl: '/api/proxy',
    
    // Прямые URL для тестирования
    directUrls: {
        isolation: 'http://localhost:8001',
        random: 'http://localhost:8002',
        juiceShop: 'http://localhost:3001'
    },
    
    // Методы определения доступности
    detectBestMode: async function() {
        console.log('Определение оптимального режима подключения...');
        
        // Пробуем прямой доступ
        try {
            const response = await fetch('http://localhost:8001/health', {
                method: 'GET',
                mode: 'no-cors',
                cache: 'no-store'
            });
            console.log('Прямой доступ возможен');
            return 'direct';
        } catch (error) {
            console.log('Прямой доступ невозможен, используем прокси');
            return 'proxy';
        }
    },
    
    // Получить URL для сервиса
    getServiceUrl: async function(serviceName) {
        if (this.mode === 'auto') {
            this.mode = await this.detectBestMode();
        }
        
        if (this.mode === 'direct') {
            return this.directUrls[serviceName];
        } else {
            // Для прокси режима возвращаем относительный путь
            return `${this.proxyBaseUrl}/${serviceName}`;
        }
    }
};

// Функция для запросов с автоматическим выбором метода
async function orchicFetch(service, endpoint, options = {}) {
    const serviceUrls = {
        'isolation': 'http://localhost:8001',
        'random': 'http://localhost:8002',
        'juice': 'http://localhost:3001'
    };
    
    const url = `${serviceUrls[service]}${endpoint}`;
    const proxyUrl = `/api/proxy/${service}${endpoint}`;
    
    console.log(`Попытка запроса к ${service}: ${url}`);
    
    // Пробуем прямой запрос
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            console.log(`✓ Прямой запрос к ${service} успешен`);
            return response;
        }
    } catch (error) {
        console.log(`✗ Прямой запрос к ${service} не удался: ${error.message}`);
    }
    
    // Если прямой не удался, пробуем через прокси
    console.log(`Пробуем прокси для ${service}...`);
    try {
        const response = await fetch(proxyUrl, options);
        if (response.ok) {
            console.log(`✓ Прокси запрос к ${service} успешен`);
            return response;
        }
    } catch (proxyError) {
        console.log(`✗ Прокси запрос также не удался: ${proxyError.message}`);
    }
    
    throw new Error(`Не удалось подключиться к ${service}`);
}
