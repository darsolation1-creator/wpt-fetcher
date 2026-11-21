import asyncio, base64, json, os, sys, time, urllib.request
sys.path.insert(0, ".")
import wptglobal

INGEST_URL = os.environ["WPT_INGEST_URL"]
INGEST_TOKEN = os.environ["WPT_INGEST_TOKEN"]
RUN_SECONDS = 5 * 3600 + 50 * 60  # ~5h50m, then the workflow re-triggers


async def fetch_once():
    tournaments = await wptglobal.fetch_wpt_tournaments()
    out = []
    for t in tournaments:
        try:
            out.append(base64.b64encode(t.SerializeToString()).decode())
        except Exception:
            continue
    return out


def push(b64list):
    payload = json.dumps({"ts": time.time(), "tournaments": b64list}).encode()
    req = urllib.request.Request(
        INGEST_URL, data=payload, method="POST",
        headers={"Content-Type": "application/json", "X-WPT-Token": INGEST_TOKEN,
                 "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read(200).decode()


async def main():
    end = time.time() + RUN_SECONDS
    while time.time() < end:
        t0 = time.time()
        try:
            b64 = await fetch_once()
            if b64:
                code, body = push(b64)
                print(f"[{time.strftime('%H:%M:%S')}] fetched {len(b64)} -> push {code} {body}", flush=True)
            else:
                print(f"[{time.strftime('%H:%M:%S')}] fetched 0 (skip push)", flush=True)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] ERROR {e}", flush=True)
        dt = time.time() - t0
        await asyncio.sleep(max(5, 60 - dt))


asyncio.run(main())
