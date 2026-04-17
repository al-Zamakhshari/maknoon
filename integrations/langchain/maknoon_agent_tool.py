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
def generate_maknoon_password(length: int = 32, no_symbols: bool = False) -> str:
    """Generates a high-entropy secure password."""
    cmd = ["MAKNOON_PLACEHOLDER", "gen", "password", "--length", str(length)]
    if no_symbols:
        cmd.append("--no-symbols")
    
    result = _run_maknoon(cmd, {}, timeout=5)
    return result.stdout.strip()

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
