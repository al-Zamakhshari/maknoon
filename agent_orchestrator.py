import requests
import json
import time
import sys
import re
from urllib.parse import urljoin

BASE_URL = "http://localhost:8080"

def trigger_ghost_tunnel():
    print("🤖 Connecting to Maknoon SSE Gateway...")
    # 1. Establish SSE session
    with requests.get(f"{BASE_URL}/sse", stream=True, timeout=60) as r:
        post_url = None
        
        # Generator to read SSE events
        def sse_events():
            current_event = None
            for line in r.iter_lines():
                if line:
                    line_str = line.decode('utf-8')
                    if line_str.startswith("event:"):
                        current_event = line_str[6:].strip()
                    elif line_str.startswith("data:"):
                        data = line_str[5:].strip()
                        yield current_event, data
                        current_event = None

        events = sse_events()
        
        # 2. Get the endpoint
        for ev_type, data in events:
            if ev_type == "endpoint" or "/message" in data:
                post_url = urljoin(BASE_URL, data)
                print(f"🤖 Discovered POST endpoint: {post_url}")
                break
        
        if not post_url:
            print("❌ Failed to discover POST endpoint.")
            return None

        # 3. Trigger the tool
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "tunnel_listen",
                "arguments": {"wormhole": True}
            },
            "id": "mission-rigor"
        }
        
        resp = requests.post(post_url, json=payload)
        if resp.status_code not in [200, 202]:
            print(f"❌ POST failed ({resp.status_code}): {resp.text}")
            return None

        print(f"🤖 Tool call accepted. Waiting for result in SSE stream...")

        # 4. Listen for the result in the SAME SSE stream
        for ev_type, data in events:
            if ev_type == "message":
                msg = json.loads(data)
                if msg.get("id") == "mission-rigor":
                    print(f"🤖 Received Tool Result: {data}")
                    result = msg.get("result", {})
                    content = result.get("content", [])
                    if content:
                        raw_text = content[0]['text']
                        res_data = json.loads(raw_text)
                        return res_data.get("code")
                    else:
                        print(f"❌ Result has no content: {data}")
                        return None
    return None

if __name__ == "__main__":
    code = trigger_ghost_tunnel()
    if code:
        print(f"✅ GHOST_CODE:{code}")
    else:
        sys.exit(1)
