"""
Video Chat Server - HTTPS версия с рабочим видео
"""
import asyncio
import socket
import json
import logging
import ssl
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn

# ============================================================================
# НАСТРОЙКА ЛОГГИРОВАНИЯ
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# АВТОМАТИЧЕСКАЯ ГЕНЕРАЦИЯ SSL СЕРТИФИКАТОВ
# ============================================================================

def generate_ssl_certificates():
    """Автоматическая генерация SSL сертификатов"""
    cert_path = Path("cert.pem")
    key_path = Path("key.pem")
    
    # Если файлы уже существуют, используем их
    if cert_path.exists() and key_path.exists():
        logger.info("✅ Использую существующие SSL сертификаты")
        return str(cert_path), str(key_path)
    
    print("\n🔐 Генерация SSL сертификатов...")
    
    try:
        # Импортируем cryptography
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # Генерируем приватный ключ
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Создаем subject (владелец сертификата)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Moscow"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Moscow"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VideoChat Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        # Используем timezone-aware datetime
        now = datetime.now(timezone.utc)
        not_valid_before = now
        not_valid_after = now + timedelta(days=365)
        
        # Создаем сертификат
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_valid_before)
            .not_valid_after(not_valid_after)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.DNSName("127.0.0.1"),
                ]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256(), default_backend())
        )
        
        # Сохраняем приватный ключ
        with open(key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        # Сохраняем сертификат
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"✅ Сертификаты созданы:")
        print(f"   📄 Сертификат: {cert_path}")
        print(f"   🔑 Ключ: {key_path}")
        print(f"   ⏱️  Действителен: 365 дней")
        
        return str(cert_path), str(key_path)
        
    except ImportError:
        print("❌ ОШИБКА: Библиотека cryptography не установлена!")
        print("📦 Установите: pip install cryptography")
        return None, None
        
    except Exception as e:
        print(f"❌ Ошибка создания сертификатов: {e}")
        return None, None

# ============================================================================
# ПОЛУЧЕНИЕ IP АДРЕСОВ
# ============================================================================

def get_local_ip():
    """Получить локальный IP адрес"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

# ============================================================================
# МЕНЕДЖЕР СОЕДИНЕНИЙ
# ============================================================================

class ConnectionManager:
    """Менеджер WebSocket соединений"""
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Подключение клиента"""
        await websocket.accept()
        
        async with self.lock:
            self.active_connections[client_id] = websocket
        
        logger.info(f"✅ Подключен: {client_id}")
        
        # Отправляем приветственное сообщение
        await self._safe_send_json(websocket, {
            "type": "connected",
            "client_id": client_id,
            "message": "Соединение установлено"
        })
        
        # Уведомляем других пользователей о новом подключении
        other_users = self.get_other_clients(client_id)
        if other_users:
            await self.broadcast({
                "type": "user_joined",
                "client_id": client_id,
                "users_online": len(self.active_connections)
            }, exclude=client_id)
    
    async def disconnect(self, client_id: str):
        """Отключение клиента"""
        async with self.lock:
            if client_id in self.active_connections:
                try:
                    ws = self.active_connections[client_id]
                    await ws.close(code=1000)
                except:
                    pass
                finally:
                    if client_id in self.active_connections:
                        del self.active_connections[client_id]
                        logger.info(f"📤 Отключен: {client_id}")
        
        # Уведомляем о выходе пользователя
        await self.broadcast({
            "type": "user_left",
            "client_id": client_id,
            "users_online": len(self.active_connections)
        })
    
    async def _safe_send_json(self, websocket: WebSocket, data: dict) -> bool:
        """Безопасная отправка JSON"""
        try:
            await websocket.send_json(data)
            return True
        except Exception as e:
            logger.debug(f"Ошибка отправки: {type(e).__name__}")
            return False
    
    async def broadcast(self, message: dict, exclude: str = None):
        """Рассылка сообщения всем клиентам"""
        disconnected = []
        
        async with self.lock:
            for client_id, websocket in list(self.active_connections.items()):
                if client_id != exclude:
                    try:
                        await websocket.send_json(message)
                    except Exception:
                        disconnected.append(client_id)
        
        # Удаляем отключившихся клиентов
        for client_id in disconnected:
            await self.disconnect(client_id)
    
    async def send_to(self, target_id: str, message: dict):
        """Отправить сообщение конкретному клиенту"""
        async with self.lock:
            if target_id in self.active_connections:
                try:
                    await self.active_connections[target_id].send_json(message)
                    return True
                except Exception:
                    await self.disconnect(target_id)
        return False
    
    def get_other_clients(self, client_id: str) -> List[str]:
        """Получить список других клиентов"""
        return [cid for cid in self.active_connections.keys() if cid != client_id]

# Создаем менеджер
manager = ConnectionManager()

# ============================================================================
# FASTAPI ПРИЛОЖЕНИЕ
# ============================================================================

app = FastAPI(
    title="Video Chat - HTTPS версия",
    debug=False
)

# ============================================================================
# HTML СТРАНИЦА С ИСПРАВЛЕННЫМ WEBRTC
# ============================================================================

@app.get("/")
async def home():
    """Главная страница"""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>🎥 Video Chat - HTTPS</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }}
            .container {{
                max-width: 1000px;
                margin: 0 auto;
                background: white;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }}
            h1 {{
                text-align: center;
                margin-bottom: 10px;
                color: #2c3e50;
            }}
            .subtitle {{
                text-align: center;
                color: #7f8c8d;
                margin-bottom: 30px;
            }}
            .ip-box {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                font-family: 'Courier New', monospace;
                border-left: 5px solid #3498db;
            }}
            .btn-container {{
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin: 30px 0;
                justify-content: center;
            }}
            .btn {{
                padding: 15px 30px;
                border: none;
                border-radius: 10px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                display: flex;
                align-items: center;
                gap: 10px;
                min-width: 200px;
                justify-content: center;
            }}
            .btn-primary {{
                background: linear-gradient(135deg, #3498db, #2980b9);
                color: white;
            }}
            .btn-primary:hover {{
                transform: translateY(-3px);
                box-shadow: 0 10px 20px rgba(52, 152, 219, 0.3);
            }}
            .btn-success {{
                background: linear-gradient(135deg, #2ecc71, #27ae60);
                color: white;
            }}
            .btn-success:hover {{
                transform: translateY(-3px);
                box-shadow: 0 10px 20px rgba(46, 204, 113, 0.3);
            }}
            .btn-danger {{
                background: linear-gradient(135deg, #e74c3c, #c0392b);
                color: white;
            }}
            .btn-danger:hover {{
                transform: translateY(-3px);
                box-shadow: 0 10px 20px rgba(231, 76, 60, 0.3);
            }}
            .btn:disabled {{
                opacity: 0.5;
                cursor: not-allowed;
                transform: none !important;
                box-shadow: none !important;
            }}
            .video-container {{
                display: flex;
                gap: 20px;
                margin: 30px 0;
                flex-wrap: wrap;
                justify-content: center;
            }}
            .video-box {{
                flex: 1;
                min-width: 300px;
                max-width: 600px;
                background: #2c3e50;
                border-radius: 15px;
                overflow: hidden;
                border: 3px solid #34495e;
            }}
            video {{
                width: 100%;
                height: 400px;
                background: #000;
                display: block;
            }}
            .video-label {{
                padding: 15px;
                background: rgba(0,0,0,0.7);
                color: white;
                text-align: center;
                font-weight: bold;
            }}
            .status {{
                padding: 20px;
                margin: 20px 0;
                background: #e8f5e9;
                border-radius: 10px;
                border-left: 5px solid #2ecc71;
                font-family: monospace;
            }}
            .status.error {{
                background: #ffebee;
                border-left-color: #e74c3c;
            }}
            .status.warning {{
                background: #fff3e0;
                border-left-color: #ff9800;
            }}
            .ssl-warning {{
                background: #fff3e0;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                border-left: 5px solid #f39c12;
            }}
            .ssl-warning h3 {{
                color: #e67e22;
                margin-top: 0;
                display: flex;
                align-items: center;
                gap: 10px;
            }}
            .instructions {{
                background: #f0f7ff;
                padding: 25px;
                border-radius: 10px;
                margin: 30px 0;
                border-left: 5px solid #3498db;
            }}
            .instructions h3 {{
                margin-top: 0;
                color: #2980b9;
            }}
            .instructions ol {{
                line-height: 1.8;
                margin-left: 20px;
            }}
            .link-box {{
                background: #e3f2fd;
                padding: 15px;
                border-radius: 8px;
                margin: 15px 0;
                font-family: monospace;
                word-break: break-all;
                cursor: pointer;
                transition: background 0.3s;
            }}
            .link-box:hover {{
                background: #bbdefb;
            }}
            .users-online {{
                background: #fff3e0;
                padding: 15px;
                border-radius: 10px;
                margin: 15px 0;
                text-align: center;
                font-weight: bold;
                border-left: 5px solid #ff9800;
            }}
            @media (max-width: 768px) {{
                .container {{
                    padding: 20px;
                }}
                .video-box {{
                    min-width: 100%;
                }}
                .btn {{
                    width: 100%;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎥 Video Chat - HTTPS версия</h1>
            <div class="subtitle">Безопасное соединение с автоматическим SSL</div>
            
            <div class="ip-box">
                <strong>🌐 Сетевые адреса:</strong><br>
                📍 Локальный IP: <strong>{LOCAL_IP}</strong><br>
                🔐 Порт HTTPS: <strong>8443</strong><br>
                📡 Протокол: <strong>HTTPS</strong>
            </div>
            
            <div class="ssl-warning">
                <h3>⚠️ Внимание: Самоподписанный SSL сертификат</h3>
                <p>При первом подключении браузер покажет предупреждение о безопасности.</p>
                <p>Это нормально! Нажмите:</p>
                <ul>
                    <li><strong>Chrome:</strong> "Дополнительно" → "Перейти на сайт (небезопасно)"</li>
                    <li><strong>Firefox:</strong> "Дополнительно" → "Принять риск и продолжить"</li>
                    <li><strong>Edge:</strong> "Дополнительно" → "Перейти на веб-страницу"</li>
                </ul>
            </div>
            
            <div class="users-online" id="usersOnline">
                👥 Участников онлайн: <span id="onlineCount">0</span>
            </div>
            
            <div class="btn-container">
                <button class="btn btn-primary" onclick="connectToServer()" id="connectBtn">
                    <span>🔗</span>
                    <span>Подключиться к серверу</span>
                </button>
                <button class="btn btn-success" onclick="toggleCamera()" id="cameraBtn">
                    <span>📹</span>
                    <span>Включить камеру</span>
                </button>
                <button class="btn btn-danger" onclick="disconnectAll()" id="disconnectBtn" style="display: none;">
                    <span>❌</span>
                    <span>Отключиться</span>
                </button>
            </div>
            
            <div class="status" id="status">
                ✅ HTTPS сервер запущен. Нажмите "Подключиться к серверу"
            </div>
            
            <div class="video-container">
                <div class="video-box">
                    <video id="localVideo" autoplay muted playsinline></video>
                    <div class="video-label">Вы</div>
                </div>
                <div class="video-box">
                    <video id="remoteVideo" autoplay playsinline></video>
                    <div class="video-label" id="remoteLabel">Ожидание участников</div>
                </div>
            </div>
            
            <div class="instructions">
                <h3>📋 Как подключить других участников:</h3>
                <ol>
                    <li>Отправьте им эту ссылку:
                        <div class="link-box" onclick="copyLink()">
                            https://{LOCAL_IP}:8443
                        </div>
                    </li>
                    <li>На их устройствах откройте эту ссылку в браузере</li>
                    <li>Примите предупреждение о SSL сертификате (1 раз)</li>
                    <li>Нажмите "Подключиться к серверу" на всех устройствах</li>
                    <li>Нажмите "Включить камеру" на всех устройствах</li>
                    <li>Наслаждайтесь безопасным видеозвонком! 🎉</li>
                </ol>
            </div>
        </div>
        
        <script>
            // ============================================================================
            // ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
            // ============================================================================
            
            let ws = null;
            let localStream = null;
            let peerConnection = null;
            let isConnected = false;
            let cameraEnabled = false;
            let clientId = null;
            let remoteClientId = null;
            
            // ============================================================================
            // ДОМ ЭЛЕМЕНТЫ
            // ============================================================================
            
            const connectBtn = document.getElementById('connectBtn');
            const cameraBtn = document.getElementById('cameraBtn');
            const disconnectBtn = document.getElementById('disconnectBtn');
            const statusEl = document.getElementById('status');
            const localVideo = document.getElementById('localVideo');
            const remoteVideo = document.getElementById('remoteVideo');
            const remoteLabel = document.getElementById('remoteLabel');
            const onlineCountEl = document.getElementById('onlineCount');
            const usersOnlineEl = document.getElementById('usersOnline');
            
            // ============================================================================
            // УТИЛИТЫ
            // ============================================================================
            
            function updateStatus(message, type = '') {{
                statusEl.textContent = message;
                statusEl.className = 'status ' + type;
                console.log('Статус:', message);
            }}
            
            function updateOnlineCount(count) {{
                onlineCountEl.textContent = count;
                if (count > 1) {{
                    usersOnlineEl.style.background = '#e8f5e9';
                    usersOnlineEl.style.borderLeftColor = '#2ecc71';
                }}
            }}
            
            function copyLink() {{
                const link = 'https://{LOCAL_IP}:8443';
                navigator.clipboard.writeText(link).then(() => {{
                    alert('✅ Ссылка скопирована:\\n' + link);
                }});
            }}
            
            // ============================================================================
            // WEBSOCKET СОЕДИНЕНИЕ
            // ============================================================================
            
            async function connectToServer() {{
                if (isConnected && ws && ws.readyState === WebSocket.OPEN) {{
                    updateStatus('✅ Уже подключено к серверу');
                    return;
                }}
                
                clientId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
                
                connectBtn.disabled = true;
                connectBtn.innerHTML = '<span>🔄</span><span>Подключаемся...</span>';
                updateStatus('🔄 Подключаемся к серверу...');
                
                try {{
                    // Используем WSS для HTTPS
                    const wsUrl = 'wss://' + window.location.hostname + ':8443/ws/' + clientId;
                    console.log('Подключаемся к:', wsUrl);
                    
                    ws = new WebSocket(wsUrl);
                    
                    ws.onopen = onWebSocketOpen;
                    ws.onmessage = onWebSocketMessage;
                    ws.onclose = onWebSocketClose;
                    ws.onerror = onWebSocketError;
                    
                }} catch (error) {{
                    console.error('Ошибка подключения:', error);
                    updateStatus('❌ Ошибка: ' + error.message, 'error');
                    connectBtn.disabled = false;
                    connectBtn.innerHTML = '<span>🔗</span><span>Подключиться к серверу</span>';
                }}
            }}
            
            function onWebSocketOpen() {{
                console.log('✅ WebSocket подключен');
                isConnected = true;
                
                updateStatus('✅ Подключено к серверу');
                connectBtn.innerHTML = '<span>✅</span><span>Подключено</span>';
                disconnectBtn.style.display = 'flex';
                cameraBtn.disabled = false;
                
                // Запрашиваем список пользователей
                sendMessage('get_users', {{}});
            }}
            
            function onWebSocketMessage(event) {{
                try {{
                    const data = JSON.parse(event.data);
                    console.log('Получено:', data.type);
                    
                    switch(data.type) {{
                        case 'connected':
                            console.log('Сервер подтвердил подключение');
                            break;
                            
                        case 'user_joined':
                            console.log('Новый пользователь подключился:', data.client_id);
                            updateOnlineCount(data.users_online);
                            
                            // Если у нас включена камера и это второй пользователь
                            if (cameraEnabled && data.users_online === 2) {{
                                remoteClientId = data.client_id;
                                updateStatus('🔄 Подключаюсь к новому участнику...');
                                createPeerConnection();
                            }}
                            break;
                            
                        case 'user_left':
                            console.log('Пользователь отключился:', data.client_id);
                            updateOnlineCount(data.users_online);
                            
                            if (remoteClientId === data.client_id) {{
                                remoteClientId = null;
                                remoteLabel.textContent = 'Участник отключился';
                                updateStatus('👤 Участник отключился');
                                
                                if (peerConnection) {{
                                    peerConnection.close();
                                    peerConnection = null;
                                    remoteVideo.srcObject = null;
                                }}
                            }}
                            break;
                            
                        case 'users_list':
                            console.log('Список пользователей:', data.users);
                            updateOnlineCount(data.users.length);
                            
                            // Если есть другие пользователи и у нас включена камера
                            if (data.users.length >= 2 && cameraEnabled) {{
                                const otherUsers = data.users.filter(id => id !== clientId);
                                if (otherUsers.length > 0) {{
                                    remoteClientId = otherUsers[0];
                                    updateStatus('🔄 Подключаюсь к участнику...');
                                    createPeerConnection();
                                }}
                            }}
                            break;
                            
                        case 'offer':
                            console.log('Получен офер от:', data.sender);
                            remoteClientId = data.sender;
                            handleOffer(data);
                            break;
                            
                        case 'answer':
                            console.log('Получен ответ от:', data.sender);
                            handleAnswer(data);
                            break;
                            
                        case 'ice_candidate':
                            console.log('Получен ICE candidate от:', data.sender);
                            handleIceCandidate(data);
                            break;
                    }}
                }} catch (error) {{
                    console.error('Ошибка обработки сообщения:', error);
                }}
            }}
            
            function onWebSocketClose() {{
                console.log('📤 WebSocket отключен');
                isConnected = false;
                cameraEnabled = false;
                
                updateStatus('❌ Соединение потеряно', 'error');
                connectBtn.disabled = false;
                connectBtn.innerHTML = '<span>🔗</span><span>Подключиться к серверу</span>';
                disconnectBtn.style.display = 'none';
                cameraBtn.disabled = true;
                cameraBtn.innerHTML = '<span>📹</span><span>Включить камеру</span>';
                updateOnlineCount(0);
                
                if (localStream) {{
                    localStream.getTracks().forEach(track => track.stop());
                    localStream = null;
                    localVideo.srcObject = null;
                }}
                
                if (peerConnection) {{
                    peerConnection.close();
                    peerConnection = null;
                    remoteVideo.srcObject = null;
                }}
            }}
            
            function onWebSocketError(error) {{
                console.error('❌ WebSocket ошибка:', error);
                updateStatus('⚠️ Ошибка соединения', 'error');
            }}
            
            function sendMessage(type, data) {{
                if (ws && ws.readyState === WebSocket.OPEN) {{
                    ws.send(JSON.stringify({{
                        type: type,
                        client_id: clientId,
                        ...data
                    }}));
                }}
            }}
            
            // ============================================================================
            // УПРАВЛЕНИЕ КАМЕРОЙ
            // ============================================================================
            
            async function toggleCamera() {{
                if (!cameraEnabled) {{
                    await startCamera();
                }} else {{
                    stopCamera();
                }}
            }}
            
            async function startCamera() {{
                try {{
                    updateStatus('🔄 Запрашиваю доступ к камере...');
                    
                    localStream = await navigator.mediaDevices.getUserMedia({{
                        video: {{
                            width: {{ ideal: 1280 }},
                            height: {{ ideal: 720 }},
                            facingMode: "user"
                        }},
                        audio: true
                    }});
                    
                    localVideo.srcObject = localStream;
                    cameraEnabled = true;
                    cameraBtn.innerHTML = '<span>⏹️</span><span>Выключить камеру</span>';
                    cameraBtn.classList.remove('btn-success');
                    cameraBtn.classList.add('btn-danger');
                    
                    updateStatus('✅ Камера включена');
                    
                    // Запрашиваем список пользователей для соединения
                    if (isConnected) {{
                        sendMessage('get_users', {{}});
                    }}
                    
                }} catch (error) {{
                    console.error('Ошибка камеры:', error);
                    updateStatus('❌ Ошибка доступа к камере', 'error');
                }}
            }}
            
            function stopCamera() {{
                if (localStream) {{
                    localStream.getTracks().forEach(track => track.stop());
                    localStream = null;
                    localVideo.srcObject = null;
                    
                    cameraEnabled = false;
                    cameraBtn.innerHTML = '<span>📹</span><span>Включить камеру</span>';
                    cameraBtn.classList.remove('btn-danger');
                    cameraBtn.classList.add('btn-success');
                    
                    updateStatus('📴 Камера выключена', 'warning');
                    
                    if (peerConnection) {{
                        peerConnection.close();
                        peerConnection = null;
                        remoteVideo.srcObject = null;
                        remoteLabel.textContent = 'Ожидание участников';
                    }}
                }}
            }}
            
            // ============================================================================
            // WEBRTC СОЕДИНЕНИЕ (ИСПРАВЛЕННОЕ)
            // ============================================================================
            
            async function createPeerConnection() {{
                if (peerConnection) {{
                    console.log('Peer connection уже существует');
                    return;
                }}
                
                if (!localStream) {{
                    console.log('Нет локального потока');
                    return;
                }}
                
                if (!remoteClientId) {{
                    console.log('Нет удаленного клиента');
                    return;
                }}
                
                console.log('Создаю peer connection для:', remoteClientId);
                updateStatus('🔄 Устанавливаю видеосоединение...');
                
                try {{
                    // Конфигурация с STUN серверами
                    const configuration = {{
                        iceServers: [
                            {{ urls: 'stun:stun.l.google.com:19302' }},
                            {{ urls: 'stun:stun1.l.google.com:19302' }},
                            {{ urls: 'stun:stun2.l.google.com:19302' }}
                        ],
                        iceCandidatePoolSize: 10
                    }};
                    
                    peerConnection = new RTCPeerConnection(configuration);
                    
                    // Добавляем локальные треки
                    localStream.getTracks().forEach(track => {{
                        peerConnection.addTrack(track, localStream);
                    }});
                    
                    // Обработка ICE кандидатов
                    peerConnection.onicecandidate = (event) => {{
                        if (event.candidate) {{
                            console.log('Отправляю ICE candidate');
                            sendMessage('ice_candidate', {{
                                candidate: event.candidate,
                                target: remoteClientId
                            }});
                        }}
                    }};
                    
                    // Получение удаленного потока
                    peerConnection.ontrack = (event) => {{
                        console.log('Получен удаленный поток');
                        if (event.streams && event.streams[0]) {{
                            remoteVideo.srcObject = event.streams[0];
                            remoteLabel.textContent = 'Участник (подключено)';
                            updateStatus('✅ Видеосоединение установлено!');
                        }}
                    }};
                    
                    // Отслеживание состояния соединения
                    peerConnection.oniceconnectionstatechange = () => {{
                        console.log('ICE состояние:', peerConnection.iceConnectionState);
                    }};
                    
                    peerConnection.onconnectionstatechange = () => {{
                        console.log('Состояние соединения:', peerConnection.connectionState);
                    }};
                    
                    // Создаем офер
                    const offer = await peerConnection.createOffer({{
                        offerToReceiveAudio: true,
                        offerToReceiveVideo: true
                    }});
                    
                    await peerConnection.setLocalDescription(offer);
                    
                    // Отправляем офер
                    sendMessage('offer', {{
                        offer: offer,
                        target: remoteClientId
                    }});
                    
                    updateStatus('🔄 Отправляю запрос на соединение...');
                    
                }} catch (error) {{
                    console.error('Ошибка создания peer connection:', error);
                    updateStatus('❌ Ошибка WebRTC: ' + error.message, 'error');
                }}
            }}
            
            async function handleOffer(data) {{
                console.log('Обрабатываю офер от:', data.sender);
                updateStatus('🔄 Принимаю входящее соединение...');
                
                if (!localStream) {{
                    console.log('Нет локального потока');
                    return;
                }}
                
                if (peerConnection) {{
                    peerConnection.close();
                }}
                
                try {{
                    const configuration = {{
                        iceServers: [
                            {{ urls: 'stun:stun.l.google.com:19302' }},
                            {{ urls: 'stun:stun1.l.google.com:19302' }}
                        ]
                    }};
                    
                    peerConnection = new RTCPeerConnection(configuration);
                    
                    // Добавляем локальные треки
                    localStream.getTracks().forEach(track => {{
                        peerConnection.addTrack(track, localStream);
                    }});
                    
                    // ICE кандидаты
                    peerConnection.onicecandidate = (event) => {{
                        if (event.candidate) {{
                            sendMessage('ice_candidate', {{
                                candidate: event.candidate,
                                target: data.sender
                            }});
                        }}
                    }};
                    
                    // Удаленный поток
                    peerConnection.ontrack = (event) => {{
                        console.log('Получен удаленный поток');
                        if (event.streams && event.streams[0]) {{
                            remoteVideo.srcObject = event.streams[0];
                            remoteLabel.textContent = 'Участник (подключено)';
                            updateStatus('✅ Видеосоединение установлено!');
                        }}
                    }};
                    
                    // Устанавливаем удаленное описание
                    await peerConnection.setRemoteDescription(new RTCSessionDescription(data.offer));
                    
                    // Создаем ответ
                    const answer = await peerConnection.createAnswer();
                    await peerConnection.setLocalDescription(answer);
                    
                    // Отправляем ответ
                    sendMessage('answer', {{
                        answer: answer,
                        target: data.sender
                    }});
                    
                }} catch (error) {{
                    console.error('Ошибка обработки офера:', error);
                }}
            }}
            
            async function handleAnswer(data) {{
                if (!peerConnection) return;
                
                try {{
                    await peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
                    console.log('Answer установлен');
                }} catch (error) {{
                    console.error('Ошибка установки answer:', error);
                }}
            }}
            
            async function handleIceCandidate(data) {{
                if (!peerConnection) return;
                
                try {{
                    await peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
                    console.log('ICE candidate добавлен');
                }} catch (error) {{
                    console.error('Ошибка добавления ICE candidate:', error);
                }}
            }}
            
            // ============================================================================
            // УПРАВЛЕНИЕ СОЕДИНЕНИЕМ
            // ============================================================================
            
            function disconnectAll() {{
                if (ws) {{
                    ws.close(1000, 'Пользователь отключился');
                    ws = null;
                }}
                
                if (peerConnection) {{
                    peerConnection.close();
                    peerConnection = null;
                }}
                
                stopCamera();
                
                isConnected = false;
                remoteVideo.srcObject = null;
                remoteLabel.textContent = 'Ожидание участников';
                
                updateStatus('📤 Отключено от сервера', 'warning');
                connectBtn.disabled = false;
                connectBtn.innerHTML = '<span>🔗</span><span>Подключиться к серверу</span>';
                disconnectBtn.style.display = 'none';
                cameraBtn.disabled = true;
                updateOnlineCount(0);
            }}
            
            // ============================================================================
            // ИНИЦИАЛИЗАЦИЯ
            // ============================================================================
            
            function init() {{
                console.log('🚀 Инициализация страницы');
                
                window.addEventListener('beforeunload', () => {{
                    if (ws) ws.close(1000, 'Страница закрывается');
                    if (localStream) localStream.getTracks().forEach(track => track.stop());
                }});
                
                // Автоматическое подключение через 1 секунду
                setTimeout(() => {{
                    connectToServer();
                }}, 1000);
                
                updateStatus('✅ Страница загружена');
            }}
            
            window.addEventListener('load', init);
        </script>
    </body>
    </html>
    """)

# ============================================================================
# WEBSOCKET HANDLER С ПРАВИЛЬНОЙ МАРШРУТИЗАЦИЕЙ
# ============================================================================

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint с правильной маршрутизацией"""
    try:
        await manager.connect(websocket, client_id)
        
        try:
            while True:
                try:
                    # Получаем сообщение
                    data = await websocket.receive_json()
                    await handle_message(websocket, client_id, data)
                    
                except WebSocketDisconnect:
                    logger.info(f"Клиент отключился: {client_id}")
                    break
                    
                except Exception as e:
                    logger.error(f"Ошибка обработки сообщения {client_id}: {type(e).__name__}")
                    break
                    
        except Exception as e:
            logger.error(f"Критическая ошибка в цикле {client_id}: {type(e).__name__}")
            
    except Exception as e:
        logger.error(f"Ошибка подключения {client_id}: {type(e).__name__}")
        
    finally:
        # Отключаем клиента
        await manager.disconnect(client_id)

async def handle_message(websocket: WebSocket, client_id: str, data: dict):
    """Обработка сообщений с правильной маршрутизацией"""
    message_type = data.get("type")
    
    if message_type == "get_users":
        # Отправляем список пользователей
        users = list(manager.active_connections.keys())
        await manager._safe_send_json(websocket, {
            "type": "users_list",
            "users": users,
            "users_online": len(users)
        })
        
    elif message_type == "offer":
        # Пересылаем офер конкретному получателю
        target = data.get("target")
        if target and target in manager.active_connections:
            await manager.send_to(target, {
                "type": "offer",
                "offer": data.get("offer"),
                "sender": client_id
            })
        
    elif message_type == "answer":
        # Пересылаем ответ конкретному получателю
        target = data.get("target")
        if target and target in manager.active_connections:
            await manager.send_to(target, {
                "type": "answer",
                "answer": data.get("answer"),
                "sender": client_id
            })
        
    elif message_type == "ice_candidate":
        # Пересылаем ICE кандидат конкретному получателю
        target = data.get("target")
        if target and target in manager.active_connections:
            await manager.send_to(target, {
                "type": "ice_candidate",
                "candidate": data.get("candidate"),
                "sender": client_id
            })

# ============================================================================
# ЗАПУСК СЕРВЕРА
# ============================================================================

def main():
    """Запуск сервера"""
    print("\n" + "="*70)
    print("🚀 ЗАПУСК HTTPS ВИДЕОЧАТ СЕРВЕРА")
    print("="*70)
    
    # Генерируем SSL сертификаты
    cert_path, key_path = generate_ssl_certificates()
    
    if not cert_path or not key_path:
        print("\n❌ НЕ УДАЛОСЬ СОЗДАТЬ SSL СЕРТИФИКАТЫ")
        print("📦 Установите cryptography: pip install cryptography")
        print("🔄 Запускаю HTTP версию на порту 8000...")
        
        # Fallback на HTTP
        try:
            uvicorn.run(
                app,
                host="0.0.0.0",
                port=8000,
                log_level="info"
            )
        except Exception as e:
            print(f"❌ Ошибка запуска HTTP: {e}")
        return
    
    print(f"📍 Локальный IP: {LOCAL_IP}")
    print(f"🔐 Порт HTTPS: 8443")
    print("\n📱 ДЛЯ ПОДКЛЮЧЕНИЯ:")
    print(f"   1. На этом компьютере: https://localhost:8443")
    print(f"   2. На других устройствах: https://{LOCAL_IP}:8443")
    print("\n⚠️  ПРИ ПЕРВОМ ПОДКЛЮЧЕНИИ:")
    print("   1. Браузер покажет предупреждение о безопасности")
    print("   2. Нажмите 'Дополнительно' → 'Перейти на сайт'")
    print("   3. Это нужно сделать только один раз")
    print("="*70)
    print("\n🎥 ДЛЯ ТЕСТИРОВАНИЯ ВИДЕО:")
    print("   1. Откройте две вкладки браузера")
    print("   2. В каждой вкладке нажмите 'Подключиться к серверу'")
    print("   3. В каждой вкладке нажмите 'Включить камеру'")
    print("   4. Видео должно появиться автоматически!")
    print("="*70)
    
    # Запускаем HTTPS сервер
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8443,
            ssl_certfile=cert_path,
            ssl_keyfile=key_path,
            log_level="info",
            loop="asyncio",
            timeout_keep_alive=30,
            access_log=False
        )
    except KeyboardInterrupt:
        print("\n\n🛑 Сервер остановлен пользователем")
    except Exception as e:
        print(f"\n❌ Ошибка запуска HTTPS сервера: {e}")

if __name__ == "__main__":
    main()