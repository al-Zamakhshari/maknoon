import os
import subprocess
import json
import shutil
from typing import Dict, Any, List, Optional, Union
from langchain_core.tools import tool

def get_binary_path() -> str:
    """Dynamically resolves the maknoon binary path."""
    return os.environ.get("MAKNOON_BINARY") or shutil.which("maknoon") or "maknoon"

def _run_maknoon(cmd: List[str], env: Dict[str, str], timeout: int = 10) -> subprocess.CompletedProcess:
    """Helper to run maknoon with standard timeout and environment."""
    full_env = os.environ.copy()
    full_env.update(env)
    # Global JSON mode for Agentic AI
    full_env["MAKNOON_JSON"] = "1"
    
    binary = get_binary_path()
    if cmd[0] == "MAKNOON_PLACEHOLDER":
        cmd[0] = binary

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=full_env,
        timeout=timeout,
        check=False
    )

def _parse_json_result(result: subprocess.CompletedProcess) -> Dict[str, Any]:
    """Parses JSON from stdout or fallback to stderr/error object."""
    try:
        if result.stdout.strip():
            return json.loads(result.stdout)
        if result.stderr.strip():
            return json.loads(result.stderr)
    except json.JSONDecodeError:
        pass
    
    return {
        "status": "error",
        "error": result.stderr.strip() or f"Process exited with code {result.returncode}",
        "exit_code": result.returncode
    }

@tool
def get_maknoon_secret(service_name: str, vault_name: str = "default") -> Dict[str, Any]:
    """Retrieves a secret (username, password, note) from the Maknoon vault."""
    env = {}
    if "MAKNOON_PASSPHRASE" not in os.environ:
        return {"status": "error", "error": "MAKNOON_PASSPHRASE not set in environment"}

    cmd = ["MAKNOON_PLACEHOLDER", "vault", "get", service_name, "--vault", vault_name]
    result = _run_maknoon(cmd, env)
    return _parse_json_result(result)

@tool
def set_maknoon_secret(
    service_name: str, 
    password: str, 
    username: str = "", 
    note: str = "", 
    vault_name: str = "default"
) -> Dict[str, Any]:
    """Stores or updates a secret in the Maknoon vault."""
    # SECURITY: Pass password via environment variable to avoid process list exposure
    env = {"MAKNOON_PASSWORD": password}
    cmd = [
        "MAKNOON_PLACEHOLDER", "vault", "set", service_name,
        "--vault", vault_name,
        "--user", username, "--note", note
    ]
    result = _run_maknoon(cmd, env)
    return _parse_json_result(result)

@tool
def decrypt_maknoon_file(file_path: str, private_key_path: Optional[str] = None) -> Union[str, Dict[str, Any]]:
    """Decrypts a .makn file and returns its content as a string."""
    env = {}
    if private_key_path:
        env["MAKNOON_PRIVATE_KEY"] = private_key_path
    
    # Disable global JSON mode for this specific command to get raw data
    env["MAKNOON_JSON"] = "0"

    cmd = ["MAKNOON_PLACEHOLDER", "decrypt", file_path, "-o", "-", "--quiet"]
    result = _run_maknoon(cmd, env, timeout=30)
    
    if result.returncode != 0:
        return _parse_json_result(result)
    
    return result.stdout

@tool
def encrypt_maknoon_file(
    input_path: str, 
    output_path: str, 
    public_key_path: Optional[str] = None, 
    compress: bool = False,
    overwrite: bool = False
) -> Dict[str, Any]:
    """Encrypts a file or directory using Maknoon."""
    env = {}
    if public_key_path:
        env["MAKNOON_PUBLIC_KEY"] = public_key_path
    
    cmd = ["MAKNOON_PLACEHOLDER", "encrypt", input_path, "-o", output_path, "--quiet"]
    if compress:
        cmd.append("--compress")
    if overwrite:
        cmd.append("--overwrite")
    
    result = _run_maknoon(cmd, env, timeout=60)
    return _parse_json_result(result)

@tool
def send_maknoon_file(
    file_path: Optional[str] = None, 
    text: Optional[str] = None,
    public_key_path: Optional[str] = None,
    stealth: bool = False,
    rendezvous_url: Optional[str] = None,
    transit_relay: Optional[str] = None
) -> Dict[str, Any]:
    """Sends a file, directory, or raw text via secure ephemeral P2P and returns a one-time code."""
    cmd = ["MAKNOON_PLACEHOLDER", "send", "--json"]
    if text:
        cmd.extend(["--text", text])
    elif file_path:
        cmd.append(file_path)
    else:
        return {"error": "either file_path or text must be provided"}
        
    if public_key_path:
        cmd.extend(["--public-key", public_key_path])
    if stealth:
        cmd.append("--stealth")
    if rendezvous_url:
        cmd.extend(["--rendezvous-url", rendezvous_url])
    if transit_relay:
        cmd.extend(["--transit-relay", transit_relay])
    
    # This is a blocking call that waits for the receiver
    result = _run_maknoon(cmd, {}, timeout=300) 
    return _parse_json_result(result)

@tool
def receive_maknoon_file(
    code: str, 
    passphrase: Optional[str] = None, 
    private_key_path: Optional[str] = None,
    output_path: Optional[str] = None, 
    stealth: bool = False,
    rendezvous_url: Optional[str] = None,
    transit_relay: Optional[str] = None
) -> Dict[str, Any]:
    """Receives a file via secure ephemeral P2P using a code."""
    cmd = ["MAKNOON_PLACEHOLDER", "receive", code, "--json"]
    if passphrase:
        cmd.extend(["--passphrase", passphrase])
    if private_key_path:
        cmd.extend(["--private-key", private_key_path])
    if output_path:
        cmd.extend(["--output", output_path])
    if stealth:
        cmd.append("--stealth")
    if rendezvous_url:
        cmd.extend(["--rendezvous-url", rendezvous_url])
    if transit_relay:
        cmd.extend(["--transit-relay", transit_relay])
    
    result = _run_maknoon(cmd, {}, timeout=300)
    return _parse_json_result(result)

@tool
def generate_maknoon_password(length: int = 32, no_symbols: bool = False) -> Dict[str, Any]:
    """Generates a high-entropy secure password."""
    cmd = ["MAKNOON_PLACEHOLDER", "gen", "password", "--length", str(length)]
    if no_symbols:
        cmd.append("--no-symbols")
    
    result = _run_maknoon(cmd, {}, timeout=5)
    return _parse_json_result(result)

@tool
def generate_maknoon_passphrase(words: int = 4, separator: str = "-") -> Dict[str, Any]:
    """Generates a mnemonic secure passphrase."""
    cmd = ["MAKNOON_PLACEHOLDER", "gen", "passphrase", "--words", str(words), "--separator", separator]
    result = _run_maknoon(cmd, {}, timeout=5)
    return _parse_json_result(result)

@tool
def get_maknoon_file_info(file_path: str, stealth: bool = False) -> Dict[str, Any]:
    """Inspects a Maknoon encrypted file's metadata and cryptographic details."""
    cmd = ["MAKNOON_PLACEHOLDER", "info", file_path]
    if stealth:
        cmd.append("--stealth")
    
    result = _run_maknoon(cmd, {}, timeout=10)
    return _parse_json_result(result)

@tool
def list_maknoon_services(vault_name: str = "default") -> Union[List[str], Dict[str, Any]]:
    """Lists available service names in the specified vault."""
    cmd = ["MAKNOON_PLACEHOLDER", "vault", "list", "--vault", vault_name]
    result = _run_maknoon(cmd, {})
    
    parsed = _parse_json_result(result)
    if isinstance(parsed, dict) and parsed.get("status") == "error":
        return parsed
    return parsed

@tool
def split_maknoon_identity(
    name: str,
    threshold: int = 2,
    shares: int = 3,
    passphrase: Optional[str] = None
) -> Dict[str, Any]:
    """Shards a private identity into mnemonic parts (Agent Mode)."""
    cmd = ["MAKNOON_PLACEHOLDER", "identity", "split", name, "--threshold", str(threshold), "--shares", str(shares)]
    if passphrase:
        cmd.extend(["--passphrase", passphrase])
    
    result = _run_maknoon(cmd, {}, timeout=30)
    return _parse_json_result(result)

@tool
def split_maknoon_vault(
    vault_name: str = "default",
    threshold: int = 2,
    shares: int = 3,
    passphrase: Optional[str] = None
) -> Dict[str, Any]:
    """Shards a vault's master access key into mnemonic parts (Agent Mode)."""
    cmd = ["MAKNOON_PLACEHOLDER", "vault", "split", "--vault", vault_name, "--threshold", str(threshold), "--shares", str(shares)]
    if passphrase:
        cmd.extend(["--passphrase", passphrase])
    
    result = _run_maknoon(cmd, {}, timeout=30)
    return _parse_json_result(result)

@tool
def combine_maknoon_identity(
    shards: List[str],
    output_name: str = "restored_id",
    passphrase: Optional[str] = None,
    no_password: bool = False
) -> Dict[str, Any]:
    """Reconstructs a private identity from mnemonic shards (Agent Mode)."""
    cmd = ["MAKNOON_PLACEHOLDER", "identity", "combine"] + shards + ["--output", output_name]
    if no_password:
        cmd.append("--no-password")
    
    env = {}
    if passphrase:
        env["MAKNOON_PASSPHRASE"] = passphrase
        
    result = _run_maknoon(cmd, env, timeout=30)
    return _parse_json_result(result)

@tool
def publish_maknoon_identity(handle: str) -> Dict[str, Any]:
    """Anchors the active identity to the global registry (dPKI POC)."""
    cmd = ["MAKNOON_PLACEHOLDER", "identity", "publish", handle]
    result = _run_maknoon(cmd, {}, timeout=10)
    return _parse_json_result(result)

@tool
def add_maknoon_contact(
    petname: str,
    kem_pub: str,
    sig_pub: Optional[str] = None,
    note: Optional[str] = None
) -> Dict[str, Any]:
    """Adds a new trusted contact (Petname) to the local address book."""
    cmd = ["MAKNOON_PLACEHOLDER", "contact", "add", petname, "--kem-pub", kem_pub]
    if sig_pub:
        cmd.extend(["--sig-pub", sig_pub])
    if note:
        cmd.extend(["--note", note])
    
    result = _run_maknoon(cmd, {}, timeout=10)
    return _parse_json_result(result)

@tool
def list_maknoon_contacts() -> List[Dict[str, Any]]:
    """Lists all trusted contacts in the local address book."""
    cmd = ["MAKNOON_PLACEHOLDER", "contact", "list"]
    result = _run_maknoon(cmd, {}, timeout=10)
    return _parse_json_result(result)

@tool
def recover_maknoon_vault(
    shards: List[str],
    vault_name: str = "default",
    output_vault: Optional[str] = None,
    passphrase: Optional[str] = None
) -> Union[List[Dict[str, str]], Dict[str, Any]]:
    """Recovers vault contents using mnemonic shards (Agent Mode)."""
    cmd = ["MAKNOON_PLACEHOLDER", "vault", "recover"] + shards + ["--vault", vault_name]
    if output_vault:
        cmd.extend(["--output", output_vault])
        
    env = {}
    if passphrase:
        env["MAKNOON_PASSPHRASE"] = passphrase
        
    result = _run_maknoon(cmd, env, timeout=30)
    return _parse_json_result(result)

@tool
def decrypt_maknoon_file(
    input_path: str,
    output_path: str,
    passphrase: Optional[str] = None,
    private_key: Optional[str] = None,
    sender_key: Optional[str] = None,
    trust_on_first_use: bool = False
) -> Dict[str, Any]:
    """Decrypts a .makn file or directory (Agent Mode)."""
    cmd = ["MAKNOON_PLACEHOLDER", "decrypt", input_path, "-o", output_path]
    if private_key:
        cmd.extend(["--private-key", private_key])
    if sender_key:
        cmd.extend(["--sender-key", sender_key])
    if trust_on_first_use:
        cmd.append("--trust-on-first-use")
    
    env = {}
    if passphrase:
        env["MAKNOON_PASSPHRASE"] = passphrase
        
    result = _run_maknoon(cmd, env, timeout=60)
    return _parse_json_result(result)

@tool
def list_maknoon_vaults() -> List[str]:
    """Lists the names of all available Maknoon vaults."""
    # Note: Using default path. Consider making this configurable or using identity logic.
    home = os.path.expanduser("~")
    vault_dir = os.path.join(home, ".maknoon", "vaults")
    if not os.path.exists(vault_dir):
        return []
    
    try:
        vaults = [f.replace(".db", "") for f in os.listdir(vault_dir) if f.endswith(".db")]
        return sorted(vaults)
    except Exception as e:
        return [f"Error: {str(e)}"]

if __name__ == "__main__":
    print(f"--- Maknoon Agentic Tools (Binary: {get_binary_path()}) ---")
