import requests
import json

url = "https://docs-demo.quiknode.pro/"

payload = json.dumps({
    "method":
    "debug_traceTransaction",
    "params": [
        "0xffd45227ca86dbe74bbbd4d0bc2d446e50f94d6dc0e580f7ea6d1257b9f7c61b", {
            "tracer": "callTracer"
        }
    ],
    "id":
    1,
    "jsonrpc":
    "2.0"
})
headers = {'Content-Type': 'application/json'}

response = requests.request("POST", url, headers=headers, data=payload)

print(response.text)
