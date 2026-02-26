import requests
import base64
import json
import urllib.parse
import random
from datetime import datetime

# تنظیمات
SUB_SOURCES_URL = "https://raw.githubusercontent.com/punez/Repo-0/refs/heads/main/inputs.txt"  # ← USERNAME و REPO-N رو برای هر ریپو عوض کن (مثلاً Repo-1)
OUTPUT_FILE = "final.txt"  # اسم هماهنگ برای همه

def log(msg):
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] {msg}")

def fetch_sources():
    try:
        r = requests.get(SUB_SOURCES_URL, timeout=15)
        r.raise_for_status()
        urls = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")]
        log(f"Found {len(urls)} subscription URLs")
        return urls
    except Exception as e:
        log(f"Error fetching sources.txt: {e}")
        return []

def fetch_and_decode(url):
    try:
        r = requests.get(url.strip(), timeout=20)
        r.raise_for_status()
        content = r.text.strip()
        try:
            decoded = base64.b64decode(content + "===").decode("utf-8", errors="ignore")
            if "\n" in decoded or "://" in decoded:
                return decoded.splitlines()
        except:
            pass
        return content.splitlines()
    except Exception as e:
        log(f"Failed to fetch {url}: {e}")
        return []

def get_fingerprint(line):
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith("vmess://"):
            b64 = line[8:].split("#")[0]
            data = json.loads(base64.b64decode(b64 + "===").decode("utf-8", errors="ignore"))
            return "|".join(str(x).lower() for x in [
                data.get("add", ""), data.get("port", ""),
                data.get("id", ""), data.get("fp", ""),
                data.get("path", ""), data.get("net", ""),
                data.get("security", ""), data.get("type", "")
            ])
        elif line.startswith(("vless://", "trojan://")):
            url = urllib.parse.urlparse(line.split("#")[0])
            params = urllib.parse.parse_qs(url.query)
            return "|".join(str(x).lower() for x in [
                url.hostname or "",
                url.port or "443",
                url.username or "",
                params.get("fp", [""])[0],
                params.get("path", [""])[0] or params.get("serviceName", [""])[0],
                params.get("type", [""])[0],
                params.get("security", [""])[0]
            ])
        else:
            return line.split("#")[0].lower()
    except:
        return line.split("#")[0].lower()

# اجرای اصلی
log("=== Starting Filter (Repo 1-4) ===")

all_lines = []
for sub_url in fetch_sources():
    lines = fetch_and_decode(sub_url)
    all_lines.extend(lines)

log(f"Total raw lines: {len(all_lines)}")

seen = {}
for line in all_lines:
    key = get_fingerprint(line)
    if key and key not in seen:
        seen[key] = line

unique_nodes = list(seen.values())
random.shuffle(unique_nodes)  # تنوع

# بدون سقف
final_list = unique_nodes

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for node in final_list:
        f.write(node + "\n")

log(f"Done: {len(final_list)} nodes → {OUTPUT_FILE}")
