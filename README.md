### VECTOR OF THE FAILURE
A critical flaw allowing the creation of a controlled communication flow between client and server.
The vulnerability occurs because the AES decryption key is static and allows for the alteration of the POST request.

### ⚡ Attack Flow

1️⃣ **Proxy Intercept** – Traffic redirected to a proxy under the attacker's control.

2️⃣ **Decrypt with AES Key** – Messages decrypted using a static AES key stored in the client.

3️⃣ **Data Editing** – Payload can be manipulated (e.g., authentication parameters, UID, etc.).

4️⃣ **Re-encrypt** – Modified content is re-encrypted with the same key.

5️⃣ **Send to Original URL** – The tampered request is sent to the server as if it were legitimate.

### 🔑 AES Keys exposed in the client
```csharp
private static readonly byte[] AES_KEY = Encoding.UTF8.GetBytes("Yg&tc%DEuh6%Zc^8");
private static readonly byte[] AES_IV  = Encoding.UTF8.GetBytes("6oyZDr22E3ychjM%");
```

### ⚡ Attack Flow

| Step                 | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| **Proxy Intercept**  | Traffic redirected to the attacker's proxy.                                |
| **Decrypt**          | Decrypted using the static AES key in the client.                          |
| **Edit**             | Payload altered (UID, parameters, etc.).                                   |
| **Re-encrypt**       | Re-encrypted with the same key.                                            |
| **Send**             | Tampered request sent to the server as legitimate.                         |

## WITH EVERYTHING IN HAND, LET'S SET UP THE APPLICATION TO RECEIVE THE REQUESTS

> ⚠️ **MITMPROXY IS NECESSARY TO PERFORM HTTP TRAFFIC INTERCEPTION AND MANIPULATION.**

### 1️⃣ Download Files
- Download this repository by clicking **Code > Download ZIP** or using `git clone`.
- Using **Windows** is recommended for better compatibility.

### 2️⃣ Install Python
- Download and install the latest version of [Python](https://www.python.org/downloads/) (>= 3.9).
- During installation, check the **"Add Python to PATH"** option.

### 3️⃣ Install Dependencies
- Open **Command Prompt** or **PowerShell** inside the project folder.
- Install the required modules by running:

```bash
pip install -r requirements.txt
```

### 4️⃣ Configure bypass.py

- Edit the `bypass.py` file and update the addresses and information.

- Change the configuration variable so the traffic flow is redirected to your local IP (the machine where the proxy will run).

### 5️⃣ Configure the Emulator

- Install the generated/provided certificate inside the emulator (necessary for the proxy to intercept HTTP).

- Run the following command in the emulator's shell to set the proxy:

```bash
settings put global http_proxy <YOUR_IP>:8080
```

### 6️⃣ Start the Server

In the terminal, start the bypass application:

```bash
python bypass.py
```
