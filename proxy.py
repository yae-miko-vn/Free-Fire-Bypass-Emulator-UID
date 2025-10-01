import re, base64, json
from datetime import datetime, timedelta
from mitmproxy import http, connection as connections
from AES import AESUtils
import time
import random
import binascii
import requests
import LoginRes_pb2
import LoginResNew_pb2
import re
import base64
import json
import importlib.util
import sys 
pyc_file_path = "./Protobuf.cpython-313.pyc"
spec = importlib.util.spec_from_file_location("my_module", pyc_file_path) 
my_module = importlib.util.module_from_spec(spec)
sys.modules["my_module"] = my_module 
spec.loader.exec_module(my_module) 
protoUtils = my_module.ProtobufUtils()
AES = AESUtils()
def octet_stream_to_hex(octet_stream):
    hex_representation = binascii.hexlify(octet_stream)

    return hex_representation.decode()
class ModzProxyAddon:
    def __init__(self):
        # Track client connection start times for auto-disconnect
        self.connections = {}  # client -> connect time

    def client_connected(self, client: connections.Client):
        # Record when the client connected
        self.connections[client] = datetime.utcnow()

    def client_disconnected(self, client: connections.Client):
        self.connections.pop(client, None)

    async def request(self, flow: http.HTTPFlow):
        
        # Auto disconnect if connection >5min
        if(flow.request.path == "/MajorLogin"):

            decrypted_data = AES.decrypt_aes_cbc(flow.request.content.hex())
            proto_bytes = bytes.fromhex(octet_stream_to_hex(decrypted_data))

            # 2. Parse Protobuf
            login_req = LoginRes_pb2.NewLoginReq()
            login_req.ParseFromString(proto_bytes)
            
            print(login_req)
        start_time = self.connections.get(flow.client_conn)
        if start_time and datetime.utcnow() - start_time > timedelta(minutes=5):
            ip = flow.client_conn.address[0]
            print(f"[AUTO-DISCONNECT] {ip} kicked after 5 minutes")
            flow.kill()
            return

        flow.request.headers["server"] = "kibo_modz"
        # Propagate real client IP so the upstream app can target the right WS client
        try:
            client_ip = flow.client_conn.address[0]
            if client_ip:
                flow.request.headers["X-Client-IP"] = client_ip
                # Also maintain X-Forwarded-For semantics
                xff = flow.request.headers.get("X-Forwarded-For")
                flow.request.headers["X-Forwarded-For"] = f"{xff}, {client_ip}" if xff else client_ip
        except Exception:
            pass

    async def response(self, flow: http.HTTPFlow):
        if "/ver.php" in flow.request.pretty_url:
            param_value = flow.request.query.get("region")
            print(param_value)
            try:
                br_server ="http://181.215.45.200:8000/"
                sg_server = "http://143.198.202.224:8000/"
                local_server = "http://192.168.100.5:8000/"

                if param_value == "NA":
                    server = br_server
                elif param_value == "SAC":
                    server = br_server
                elif param_value == "BR":
                    server = br_server
                elif param_value == "US":
                    server == br_server
                else:
                    server = sg_server
                patch = {
                    "is_server_open": True,
                    "server_url": server,  # when deployed server ip
                    # "server_url": local_server,  # local server ip
                    "is_firewall_open": False,
                    "is_review_server": False,
                }

                resp = json.loads(flow.response.content.decode("utf-8"))
                resp.update(patch)
                print(resp)
                flow.response.content = json.dumps(resp).encode("utf-8")
            except Exception as e:
                print(f"[ERROR] Version patch failed: {e}")
                flow.response.status_code = 500
                flow.response.content = b"Try Again! or contact @kibo_modz"

        if("MajorLogin"  in flow.request.pretty_url):
            print(flow.response.content)
    # --- JWT utils ---
    def decode_jwt_no_verify(self, token):
        try:
            _, payload, _ = token.split(".")
            payload += "=" * (-len(payload) % 4)
            return json.loads(base64.urlsafe_b64decode(payload))
        except Exception:
            return {}

    def extract_jwt(self, auth_header):
        m = re.search(r"Bearer\s+([\w\-.]+)", auth_header or "")
        return m.group(1) if m else None


addons = [ModzProxyAddon()]
