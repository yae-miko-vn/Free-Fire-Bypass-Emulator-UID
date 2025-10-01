import time
import random
import binascii
import requests
import LoginRes_pb2
import LoginResNew_pb2
import re
import base64
import json
from AES import AESUtils
import random
from quart import Quart, request, Response
import requests
import urllib3
import urllib.request
from datetime import datetime, timezone
from websocket_server import start_websocket_server, send_websocket_message
import asyncio
import importlib.util
import sys 
pyc_file_path = "./Protobuf.cpython-313.pyc"
spec = importlib.util.spec_from_file_location("my_module", pyc_file_path) 
my_module = importlib.util.module_from_spec(spec)
sys.modules["my_module"] = my_module 
spec.loader.exec_module(my_module) 
protoUtils = my_module.ProtobufUtils()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WHITELIST_MSG_eng = "[FF0000][b]⚠ ACCESS DENIED ⚠[/b]\n[FFFFFF][00FFFF]Your UID is [b]NOT whitelisted[/b] for bypass.\n[FFFFFF][FFD700]📩 Please contact [b]Hex[/b] for assistance.[FFFFFF]"
msg = "[FF0000][b]ACESSO NEGADO[/b]\n[FFFFFF][00FFFF]Seu UID [b]NÃO ESTÁ LIBERADO[/b] para o bypass.\n[FFFFFF][FFD700] Por favor, contate o [b]Hex[/b] para mais detalhes.[FFFFFF]"
WHITELIST_MSG_brazil = msg.encode("utf-8")

_cache = {}

# Rastrear conexões por IP para poder fechá-las
active_connections = {}

# IPs que fizeram login - devem ter todas as conexões fechadas
logged_in_ips = set()

# Controle de notificação por IP para evitar spam no WS
last_ws_notify_at = {}
WS_NOTIFY_COOLDOWN_SECONDS = 5

async def notify_login_once(client_ip: str):
    try:
        now = time.time()
        last = last_ws_notify_at.get(client_ip, 0)
        if (now - last) >= WS_NOTIFY_COOLDOWN_SECONDS:
            await send_websocket_message(client_ip, "user_login")
            last_ws_notify_at[client_ip] = now
    except Exception:
        pass

def login_by_ip(uid: str, client_ip: str) -> bool:
    try:
        print(f"[LOGIN] Tentativa de login para UID: {uid} via IP: {client_ip}")
        
        response = requests.post("http://localhost:3000/auth-by-ip", json={"ip": client_ip})
        
        if response.status_code != 200:
            # IP não encontrado - tenta registrar
            print(f"[LOGIN] IP {client_ip} não encontrado - tentando registrar")
            register_response = requests.post("http://localhost:3000/register-ip", json={"ip": client_ip})
            if register_response.status_code != 200:
                print(f"[LOGIN] Falha ao registrar IP: {client_ip} - Status: {register_response.status_code}")
                userData = {}
                userData["uid"] = uid
                userData["first_use"] = False
                userData["ip"] = client_ip
                return userData
            
            # Atualiza UID para o IP recém-registrado
            update_response = requests.post("http://localhost:3000/update-uid-by-ip", json={"ip": client_ip, "uid": uid})
            if update_response.status_code != 200:
                print(f"[LOGIN] Falha ao atualizar UID: {uid} - Status: {update_response.status_code}")
                userData = {}
                userData["uid"] = uid
                userData["first_use"] = False
                userData["ip"] = client_ip
                return userData
            
            print(f"[LOGIN] IP {client_ip} registrado e UID {uid} atualizado com sucesso")
            userData = {}
            userData["uid"] = uid
            userData["first_use"] = False
            userData["ip"] = client_ip
            return userData

        userData = response.json().get("user")
        if not userData:
            print("[LOGIN] Resposta inválida da API")
            return True
        if userData.get("first_use"):
            print(f"[LOGIN] Primeiro uso - Atualizando UID: {uid} para IP: {client_ip}")
            update_response = requests.post("http://localhost:3000/update-uid-by-ip", 
                                         json={"ip": client_ip, "uid": uid})
            if update_response.status_code == 200:
                print(f"[LOGIN] UID {uid} atualizado com sucesso para IP {client_ip}")
                userData["uid"] = uid
                userData["first_use"] = False
                userData["ip"] = client_ip
                return userData
            else:
                print(f"[LOGIN] Falha ao atualizar UID: {uid} - Status: {update_response.status_code}")
                userData["uid"] = uid
                userData["first_use"] = False
                userData["ip"] = client_ip
                return userData
        
        if str(userData.get("uid")) == str(uid):
            print(f"[LOGIN] Login bem-sucedido para UID: {uid} via IP: {client_ip}")
            return userData
        else:
            print(f"[LOGIN] UID inválido - Esperado: {userData.get('uid')}, Recebido: {uid}")
            userData["uid"] = uid
            userData["first_use"] = False
            userData["ip"] = client_ip
            return userData
            
    except requests.exceptions.RequestException as e:
        print(f"[LOGIN] Erro de conexão com API: {e}")
        return False
    except Exception as e:
        print(f"[LOGIN] Erro inesperado: {e}")
        return False


AES = AESUtils()


def decode_jwt_no_verify(token):
    header, payload, signature = token.split(".")

    def base64url_decode(input_str):
        input_str += "=" * (4 - len(input_str) % 4)
        return base64.urlsafe_b64decode(input_str)

    decoded_payload = json.loads(base64url_decode(payload))
    return decoded_payload


def extract_jwt(auth_header):
    match = re.search(r"Bearer\s+([\w\-.]+)", auth_header)
    return match.group(1) if match else None


def octet_stream_to_hex(octet_stream):
    hex_representation = binascii.hexlify(octet_stream)

    return hex_representation.decode()


def hex_to_base64(hex_str):
    binary_data = binascii.unhexlify(hex_str)
    base64_data = base64.b64encode(binary_data)
    return base64_data.decode()


def header(auth=""):
    return {
        "User-Agent": f"Dalvik/2.1.0 (Linux; U; Android {random.randint(1,13)}; CPH2095 Build/RKQ1.211119.001)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "Authorization": f"{auth}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
    }


app = Quart(__name__)


@app.before_serving
async def _start_websocket_server():
    # Inicia o servidor WebSocket junto com o servidor HTTP
    await start_websocket_server()


def get_client_ip_from_request(req) -> str:
    try:
        ip = req.headers.get("X-Client-IP")
        if ip:
            return ip.split(",")[0].strip().replace("::ffff:", "")
        ip = req.headers.get("X-Forwarded-For", req.remote_addr)
        return ip.split(",")[0].strip().replace("::ffff:", "")
    except Exception:
        return req.remote_addr


def get_target_url(server_region: str):
    server_region = server_region.lower()

    TARGET_SERVER = "https://clientbp.common.ggbluefox.com"
    TARGET_SERVER_IND = "https://client.ind.freefiremobile.com"
    TARGET_SERVER_BR = "https://client.us.freefiremobile.com"

    # Check the server region and return the corresponding URL
    if server_region == "ind":
        return TARGET_SERVER_IND
    elif server_region == "br":
        return TARGET_SERVER_BR
    elif server_region == "us":
        return TARGET_SERVER_BR
    elif server_region == "na":
        return TARGET_SERVER_BR
    elif server_region == "sac":
        return TARGET_SERVER_BR
    else:
        return TARGET_SERVER


def hex_to_octet_stream(hex_str: str) -> bytes:
    """
    Converts a hex string (e.g., '4a6f686e') to raw bytes.
    """
    return bytes.fromhex(hex_str)


# _______________________________________________________________________________________________________________


@app.route("/MajorLogin", methods=["POST"])
async def MajorLogin():
    # Marcar este IP como logado
    client_ip = get_client_ip_from_request(request)
    logged_in_ips.add(client_ip)
    
    try:
        ip = get_client_ip_from_request(request)
        req_body = await request.get_data()

        # 1. Decrypt incoming data
        decrypted_data = AES.decrypt_aes_cbc(req_body.hex())
        proto_bytes = bytes.fromhex(octet_stream_to_hex(decrypted_data))

        # 2. Parse Protobuf
        login_req = LoginRes_pb2.NewLoginReq()
        login_req.ParseFromString(proto_bytes)

        login_req.game_name = "free fire"
        login_req.some_flag = 1
        # login_req.version = "1.114.12"
        login_req.os_info = (
            "Android OS 15 / API-35 (TP1A.220905.001/U.R4T2.1c822c2_1_3)"
        )
        login_req.device_type = "Handheld"
        login_req.carrier = "Ncell"
        login_req.connection = "WIFI"
        login_req.screen_width = 2412
        login_req.screen_height = 1080
        login_req.dpi = "480"
        login_req.cpu_info = "ARM64 FP ASIMD AES | 5260 | 8"
        login_req.total_ram = 7238
        login_req.gpu = "Adreno (TM) 720"
        login_req.gpu_version = "OpenGL ES 3.2 V@0676.65 (GIT@d4072932f4, Ie89cf9a769, 1730731391) (Date:11/04/24)"
        login_req.google_account = "Google|2872982b-c7b8-4e52-bfe5-1bf3d31de455"
        # login_req.ip = "27.34.70.3"
        login_req.language = "en"
        # login_req.open_id = "6d7a9e72a920ee120629940dc1ed2164"
        # login_req.api_level = "8"
        login_req.device_category = "Handheld"
        login_req.device_model = "OnePlus CPH2613"
        # login_req.access_token = (
        #     "f4016fb014390286c01a47f1cf8d7cef8e6ceffbf7dbcf0a07846f3bb0682b3a"
        # )
        login_req.unknown30 = 1
        login_req.carrier2 = "Ncell"
        login_req.connection2 = "WIFI"
        login_req.session_id = "7428b253defc164018c604a1ebbfebdf"
        login_req.val60 = 102783
        login_req.val61 = 50899
        login_req.val62 = 743
        login_req.val64 = 51027
        login_req.val65 = 102783
        login_req.val66 = 51027
        login_req.val67 = 102783
        login_req.val73 = 3
        login_req.lib_path = "/data/app/~~jHEWM3xbT9VVYUy8eZmOiA==/com.dts.freefireth-B_KiZCdyGM6n3eXaOUmALA==/lib/arm64"
        login_req.val76 = 1
        login_req.apk_signature = "2087f61c19f57f2af4e7feff0b24d9d9|/data/app/~~jHEWM3xbT9VVYUy8eZmOiA==/com.dts.freefireth-B_KiZCdyGM6n3eXaOUmALA==/base.apk"
        login_req.val78 = 3
        login_req.val79 = 2
        login_req.arch = "64"
        login_req.version_code = "2019118695"
        login_req.gfx_renderer = "OpenGLES2"
        login_req.max_texture_size = 16383
        login_req.cores = 8
        login_req.unknown92 = 2950
        login_req.platform = "android"
        login_req.signature = "KqsHTxnXXUCG8sxXFVB2j0AUs3+0cvY/WgLeTdfTE/KPENeJPpny2EPnJDs8C8cBVMcd1ApAoCmM9MhzDDXabISdK31SKSFSr06eVCZ4D2Yj/C7G"
        login_req.total_storage = 111117
        login_req.refresh_rate_json = '{"cur_rate":[60,90,120]}'
        login_req.unknown97 = 1
        login_req.unknown98 = 1
        # login_req.api_level_str = "8"
        # login_req.api_level_str_2 = "8"
        login_req.raw_bytes = b"\u0013RFC\u0007\u000e\\Q1"

        # 4. Re-encode Protobuf
        modified_bytes = login_req.SerializeToString()

        # 5. Encrypt it again
        encrypted = AES.encrypt_aes_cbc(hex_to_octet_stream(modified_bytes.hex()))

        # 6. Send to original server
        target_url = "https://loginbp.ggblueshark.com/MajorLogin"
        response = requests.post(
            target_url,
            data=bytes.fromhex(encrypted.hex()),
            headers=header(),
            verify=False,
        )
        print("Login Resp: ", response.content.hex())
        login_from_binary = LoginRes_pb2.MajorLoginRes()
        login_from_binary.ParseFromString(
            bytes.fromhex(octet_stream_to_hex(response.content))
        )
        uid = login_from_binary.account_id

        check_uid = login_by_ip(uid, ip)
        print(check_uid)
        if(check_uid == None):
            return Response(WHITELIST_MSG_brazil, 403, {"Connection": "close"})

        # 7. Filter unauthorized IPs
        # if ip != "103.167.233.128" or ip != "103.114.166.134":
        # if not ip in ["103.167.233.128","103.114.166.134"]:
        #     msg = '[B][00FF00]You are not allowed! [FFFFFF]Bypass is Under Update '.encode()
        #     return Response(msg, status=400)

        print("Login Resp: ", response.content.hex())
        login_from_binary = LoginResNew_pb2.MajorLoginRes()
        login_from_binary.ParseFromString(
            bytes.fromhex(octet_stream_to_hex(response.content))
        )
        br_server = "http://181.215.45.200:8000/"
        sg_server = "http://143.198.202.224:8000/"
        if login_from_binary.uf_2 in {"NA", "BR", "US"}:
            login_from_binary.uf_10 = br_server
        else:
            login_from_binary.uf_10 = sg_server

        binary_data = login_from_binary.SerializeToString()
        protobuf_hex = binary_data.hex()
        return Response(binascii.unhexlify(protobuf_hex), response.status_code, {})

        # return Response(response.content, status=response.status_code)

    except Exception as e:
        return Response(f"{e}".encode(), status=400)


@app.route("/GetLoginData", methods=["POST"])
async def GetLoginData():
    # Marcar este IP como logado
    client_ip = get_client_ip_from_request(request)
    logged_in_ips.add(client_ip)
    
    try:
        auth_header = request.headers.get("Authorization")
        jwt_token = extract_jwt(auth_header)
        decoded_payload = decode_jwt_no_verify(jwt_token)
        account_id = decoded_payload.get("account_id", 0)
        server = decoded_payload.get("lock_region", "")
    except:
        account_id = 0
        pass

    TARGET_SERVER = get_target_url(server)
    try:
        ip = get_client_ip_from_request(request)
        req_body = await request.get_data()

        # 1. Decrypt incoming data
        decrypted_data = AES.decrypt_aes_cbc(req_body.hex())
        proto_bytes = bytes.fromhex(octet_stream_to_hex(decrypted_data))

        # 2. Parse Protobuf
        login_req = LoginRes_pb2.NewLoginReq()
        login_req.ParseFromString(proto_bytes)

        # 3. Modify all fields with new data
        login_req.game_name = "free fire"
        login_req.some_flag = 1
        # login_req.version = "1.114.12"
        login_req.os_info = (
            "Android OS 15 / API-35 (TP1A.220905.001/U.R4T2.1c822c2_1_3)"
        )
        login_req.device_type = "Handheld"
        login_req.carrier = "Ncell"
        login_req.connection = "WIFI"
        login_req.screen_width = 2412
        login_req.screen_height = 1080
        login_req.dpi = "480"
        login_req.cpu_info = "ARM64 FP ASIMD AES | 5260 | 8"
        login_req.total_ram = 7238
        login_req.gpu = "Adreno (TM) 720"
        login_req.gpu_version = "OpenGL ES 3.2 V@0676.65 (GIT@d4072932f4, Ie89cf9a769, 1730731391) (Date:11/04/24)"
        login_req.google_account = "Google|2872982b-c7b8-4e52-bfe5-1bf3d31de455"
        # login_req.ip = "27.34.70.3"
        login_req.language = "en"
        # login_req.open_id = "6d7a9e72a920ee120629940dc1ed2164"
        # login_req.api_level = "8"
        login_req.device_category = "Handheld"
        login_req.device_model = "OnePlus CPH2613"
        # login_req.access_token = (
        #     "f4016fb014390286c01a47f1cf8d7cef8e6ceffbf7dbcf0a07846f3bb0682b3a"
        # )
        login_req.unknown30 = 1
        login_req.carrier2 = "Ncell"
        login_req.connection2 = "WIFI"
        login_req.session_id = "7428b253defc164018c604a1ebbfebdf"
        login_req.val60 = 102783
        login_req.val61 = 50899
        login_req.val62 = 743
        login_req.val64 = 51027
        login_req.val65 = 102783
        login_req.val66 = 51027
        login_req.val67 = 102783
        login_req.val73 = 3
        login_req.lib_path = "/data/app/~~jHEWM3xbT9VVYUy8eZmOiA==/com.dts.freefireth-B_KiZCdyGM6n3eXaOUmALA==/lib/arm64"
        login_req.val76 = 1
        login_req.apk_signature = "2087f61c19f57f2af4e7feff0b24d9d9|/data/app/~~jHEWM3xbT9VVYUy8eZmOiA==/com.dts.freefireth-B_KiZCdyGM6n3eXaOUmALA==/base.apk"
        login_req.val78 = 3
        login_req.val79 = 2
        login_req.arch = "64"
        login_req.version_code = "2019118695"
        login_req.gfx_renderer = "OpenGLES2"
        login_req.max_texture_size = 16383
        login_req.cores = 8
        login_req.unknown92 = 2950
        login_req.platform = "android"
        login_req.signature = "KqsHTxnXXUCG8sxXFVB2j0AUs3+0cvY/WgLeTdfTE/KPENeJPpny2EPnJDs8C8cBVMcd1ApAoCmM9MhzDDXabISdK31SKSFSr06eVCZ4D2Yj/C7G"
        login_req.total_storage = 111117
        login_req.refresh_rate_json = '{"cur_rate":[60,90,120]}'
        login_req.unknown97 = 1
        login_req.unknown98 = 1
        # login_req.api_level_str = "8"
        # login_req.api_level_str_2 = "8"
        login_req.raw_bytes = b"\u0013RFC\u0007\u000e\\Q1"

        # 4. Re-encode Protobuf
        modified_bytes = login_req.SerializeToString()

        # 5. Encrypt it again
        encrypted = AES.encrypt_aes_cbc(hex_to_octet_stream(modified_bytes.hex()))

        path = "/GetLoginData"
        target_url = f"{TARGET_SERVER}/{path}"
        auth_header = request.headers.get("Authorization")

        response = requests.post(
            target_url,
            data=bytes.fromhex(encrypted.hex()),
            headers=header(auth_header),
            verify=False,
        )

        print("Login Resp: ", response.content.hex())
        login_from_binary = LoginResNew_pb2.LoginRes()
        login_from_binary.ParseFromString(
            bytes.fromhex(octet_stream_to_hex(response.content))
        )
        # print(login_from_binary.account_id)

        # check_uid =await check_uid_in_mongo(login_from_binary.account_id)

        # if check_uid == False:
        #     msg = f'{WHITELIST_MSG}\n[FFFFFF]UID: {login_from_binary.account_id} '.encode()
        #     return Response(msg,400,{})
        if login_from_binary.region == "NA":
            return Response(response.content, status=response.status_code)
        else:
            login_from_binary.uf_63.uf_2 = "gin.garenanow.live"
            # login_from_binary.is_emulator = 0

            binary_data = login_from_binary.SerializeToString()
            protobuf_hex = binary_data.hex()
            return Response(binascii.unhexlify(protobuf_hex), response.status_code, {})

    except Exception as e:
        return Response(f"{e}".encode(), status=400)


# _______________________________________________________________________________________________________________


# ____ All REQ/PROXY ___


@app.route(
    "/",
    defaults={"path": ""},
    methods=[
        "POST",
    ],
)
@app.route("/<path:path>", methods=["POST"])
async def proxy(path):
    client_ip = get_client_ip_from_request(request)
    
    # Registrar esta conexão
    if client_ip not in active_connections:
        active_connections[client_ip] = []
    active_connections[client_ip].append(request)
    
    try:
        auth_header = request.headers.get("Authorization")
        jwt_token = extract_jwt(auth_header)
        decoded_payload = decode_jwt_no_verify(jwt_token)
        account_id = decoded_payload.get("account_id", 0)
        server = decoded_payload.get("lock_region", "")
    except:
        account_id = 0
        pass

    TARGET_SERVER = get_target_url(server)
    try:
        if (
            request.headers.get("server") == "kibo_modz"
            or get_client_ip_from_request(request) == "52.79.201.15"
        ):
            # Fechar TODAS as conexões deste IP
            if client_ip in active_connections:
                for conn in active_connections[client_ip]:
                    try:
                        # Forçar fechamento da conexão
                        if hasattr(conn, 'environ') and 'wsgi.input' in conn.environ:
                            conn.environ['wsgi.input'].close()
                    except:
                        pass
                # Limpar conexões deste IP
                del active_connections[client_ip]
            await notify_login_once(client_ip)
            return Response(b'[00FF00][b]BYPASS FEITO! [FFFFFF]\n CLIQUE EM "OK" ', 403, {"Connection": "close"})

    except:
        pass
    target_url = f"{TARGET_SERVER}/{path}"

    auth_header = request.headers.get("Authorization")
    response = requests.post(
        target_url,
        await request.get_data(),
        headers={
            "User-Agent": f"Dalvik/2.1.0 (Linux; U; Android {random.randint(1,13)}; CPH2095 Build/RKQ1.211119.001)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "Authorization": auth_header,
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50",
        },
        verify=False,
    )
    
    # Limpar esta conexão da lista quando terminar
    if client_ip in active_connections:
        try:
            active_connections[client_ip].remove(request)
            if not active_connections[client_ip]:  # Se não há mais conexões
                del active_connections[client_ip]
        except:
            pass
   
    return Response(response.content, response.status_code, {})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
    