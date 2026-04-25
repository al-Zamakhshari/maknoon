import requests
import json
import time
import sys

BASE_URL = "http://localhost:8080"

def trigger_ghost_tunnel():
    print("🤖 Connecting to Maknoon SSE Gateway...")
    # 1. Start SSE session
    with requests.get(f"{BASE_URL}/sse", stream=True, timeout=30) as r:
        # We need the endpoint from the first event or the handshake
        # Simplified for this specific test: we know the session-based POST endpoint
        # In standard MCP SSE, the client gets a session ID.
        
        print("🤖 Invoking mcp_maknoon_tunnel_listen(wormhole=true)...")
        # 2. Trigger the tool
        payload = {
            "method": "tools/call",
            "params": {
                "name": "tunnel_listen",
                "arguments": {"wormhole": True}
            },
            "id": 1
        }
        
        # We use a simple POST as implemented in our SSE transport
        resp = requests.post(f"{BASE_URL}/message", json=payload)
        if resp.status_code != 200:
            print(f"❌ Tool call failed: {resp.text}")
            return None
        
        result = resp.json()
        # Parse the JSON response embedded in the MCP result text
        raw_text = result['content'][0]['text']
        data = json.loads(raw_text)
        return data.get("code")

if __name__ == "__main__":
    code = trigger_ghost_tunnel()
    if code:
        print(f"✅ GHOST_CODE:{code}")
    else:
        sys.exit(1)
