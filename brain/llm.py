import time, boto3
from botocore.exceptions import ClientError

REGION = "us-west-2"
MODELS = MODELS = {
    "fast": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "best": "us.anthropic.claude-haiku-4-5-20251001-v1:0",   # à remplacer par un Opus s'il devient accessible
}
_client = boto3.client("bedrock-runtime", region_name=REGION)
_last = 0.0

def converse(messages, model="fast", system=None, tools=None, max_retries=5):
    global _last
    kwargs = {"modelId": MODELS[model], "messages": messages}
    if system: kwargs["system"] = [{"text": system}]
    if tools: kwargs["toolConfig"] = {"tools": tools}
    for attempt in range(max_retries):
        wait = 1.1 - (time.time() - _last)   # stay under 1 request/second
        if wait > 0: time.sleep(wait)
        _last = time.time()
        try:
            return _client.converse(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ThrottlingException":
                time.sleep(2 ** attempt)     # back off, then retry
            else:
                raise
    raise RuntimeError("Bedrock throttled too many times")

if __name__ == "__main__":
    r = converse([{"role": "user", "content": [{"text": "Reply with OK"}]}])
    print(r["output"]["message"]["content"][0]["text"])