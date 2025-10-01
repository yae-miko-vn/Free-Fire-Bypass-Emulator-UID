# websocket_server.py

import asyncio
import websockets
import json
import base64
import logging
import http

# --- Configuração ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Instância Global ---
ws_server_instance = None

class WebSocketServer:
    def __init__(self, host="0.0.0.0", port=8765):
        self.host = host
        self.port = port
        self.clients_by_username = {}
        self.server = None
        self.last_request_headers = None

    def parse_basic_auth(self, auth_header):
        if not auth_header or ' ' not in auth_header:
            return None
        parts = auth_header.split(" ", 1)
        if parts[0].lower() != "basic":
            return None
        try:
            decoded = base64.b64decode(parts[1]).decode('utf-8')
            if ':' not in decoded:
                return None
            user, password = decoded.split(':', 1)
            return [user, password]
        except Exception:
            return None

    def validate_credentials(self, user, password):
        valid_users = {"indra": "indra", "username": "password"}
        return valid_users.get(user) == password

    async def register_client(self, websocket, username):
        self.clients_by_username[username] = websocket
        print(self.clients_by_username)
        logger.info(f"Cliente '{username}' conectado. Clientes online: {list(self.clients_by_username.keys())}")

    async def unregister_client(self, username):
        if username in self.clients_by_username:
            try:
                del self.clients_by_username[username]
            except KeyError:
                pass
            logger.info(f"Cliente '{username}' desconectado. Clientes online: {list(self.clients_by_username.keys())}")

    async def send_message_to_user(self, username, message_content):
        ws = self.clients_by_username.get(username)
        print("Websocket: " + str(ws))
        if not ws:
            logger.warning(f"Tentativa de enviar mensagem para o utilizador offline '{username}'")
            return

        if 1 == 1:
            payload = {"ok": True, "target": username, "msg": message_content}
            try:
                await ws.send(json.dumps(payload))
                logger.info(f"Mensagem '{message_content}' enviada para '{username}'")
            except websockets.exceptions.ConnectionClosed:
                logger.info(f"Conexão fechada durante envio para '{username}', removendo cliente.")
                await self.unregister_client(username)
            except Exception as e:
                logger.exception(f"Erro ao enviar mensagem para '{username}': {e}")
        else:
            logger.info(f"WebSocket não está aberto para '{username}', removendo cliente.")
            await self.unregister_client(username)

    async def process_request(self, path, request_headers):
        # Armazena headers para uso posterior
        logger.info(f"Autenticação aprovada para {path}")
        return None

    # <-- AQUI: assinatura CORRETA com (websocket, path)
    async def handle_client(self, connection):
    # connection.path contem o caminho da requisição (por exemplo "/meuUser")
        username = connection.remote_address[0]
        logger.info(f"Cliente '{username}' conectado (remote={connection.remote_address})")

        await self.register_client(connection, username)

        try:
            async for message in connection:
                logger.info(f"Mensagem de {username}: {message}")
        finally:
            await self.unregister_client(username)

    async def start(self):
        logger.info(f"Iniciando servidor WebSocket em ws://{self.host}:{self.port}")
        self.server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port,
            process_request=self.process_request
        )
        logger.info("Servidor WebSocket rodando.")

# --- Funções para serem chamadas pelo script principal ---
async def start_websocket_server():
    global ws_server_instance
    if ws_server_instance is None:
        ws_server_instance = WebSocketServer()
        await ws_server_instance.start()

async def send_websocket_message(username, message):
    if ws_server_instance:
        await ws_server_instance.send_message_to_user(username, message)
    else:
        logger.error("A instância do servidor WebSocket não foi iniciada.")

# --- Execução direta para testes ---
if __name__ == "__main__":
    async def main():
        await start_websocket_server()
        logger.info("Pressione CTRL+C para parar.")
        # Mantém o loop rodando indefinidamente
        await asyncio.Future()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Servidor finalizado pelo usuário.")
