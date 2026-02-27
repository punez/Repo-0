import os
import requests
import base64
import json
import urllib.parse
import random

# =======================
# ⚙️ تنظیمات
# =======================

INPUT_FOLDER = "inputs.txt"      # پوشه ورودی (داخلش txt ها هست)
OUTPUT_FOLDER = "output"      # پوشه خروجی
OUTPUT_NAME = "final.txt"     # اسم فایل خروجی
TIMEOUT = 20
MAX_DECODE_DEPTH = 5

# =======================
# ابزارها
# =======================

def ensure_dirs():
    os.makedirs(INPUT_FOLDER, exist_ok=True)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def fetch(url):
    try:
        r = requests.get(url.strip(), timeout=TIMEOUT)
        r.raise_for_status()
        return r.text.strip()
    except:
        return None

def smart_decode(text):
    """
    هرچی بیس64 چندلایه باشه decode می‌کنه
    اگر raw باشه همون رو برمی‌گردونه
    """
    for _ in range(MAX_DECODE_DEPTH):
        try:
            decoded = base64.b64decode(text + "===").decode("utf-8", errors="ignore")
            if "://" in decoded or "\n" in decoded:
                text = decoded.strip()
            else:
                break
        except:
            break
    return text

def extract_configs(text):
    lines = text.splitlines()
    valid = []
    for line in lines:
        line = line.strip()
        if line.startswith((
            "vmess://",
            "vless://",
            "trojan://",
            "ss://",
            "ssr://",
            "hy2://",
            "tuic://"
        )):
            valid.append(line)
    return valid

def get_fingerprint(line):
    """
    حذف تکراری حرفه‌ای
    """
    try:
        line = line.strip()
        if line.startswith("vmess://"):
            raw = line[8:].split("#")[0]
            data = json.loads(base64.b64decode(raw + "===").decode("utf-8", errors="ignore"))
            return "|".join(str(data.get(k,"")).lower() for k in [
                "add","port","id","net","path","type","security"
            ])
        elif line.startswith(("vless://","trojan://")):
            u = urllib.parse.urlparse(line.split("#")[0])
            q = urllib.parse.parse_qs(u.query)
            return "|".join(str(x).lower() for x in [
                u.hostname or "",
                u.port or "443",
                u.username or "",
                q.get("type",[""])[0],
                q.get("security",[""])[0],
                q.get("path",[""])[0]
            ])
        else:
            return line.split("#")[0].lower()
    except:
        return line.split("#")[0].lower()

# =======================
# اجرای اصلی
# =======================

def main():

    ensure_dirs()

    all_urls = []

    # خواندن تمام txt های داخل پوشه
    for file in os.listdir(INPUT_FOLDER):
        if file.endswith(".txt"):
            with open(os.path.join(INPUT_FOLDER, file), encoding="utf-8") as f:
                for line in f:
                    line=line.strip()
                    if line and not line.startswith("#"):
                        all_urls.append(line)

    print(f"Loaded {len(all_urls)} subscription URLs")

    collected = []

    for url in all_urls:
        data = fetch(url)
        if not data:
            continue

        decoded = smart_decode(data)
        configs = extract_configs(decoded)
        collected.extend(configs)

    print(f"Raw configs: {len(collected)}")

    # حذف تکراری
    seen = {}
    for c in collected:
        key = get_fingerprint(c)
        if key and key not in seen:
            seen[key] = c

    final = list(seen.values())

    random.shuffle(final)

    print(f"Unique configs: {len(final)}")

    output_path = os.path.join(OUTPUT_FOLDER, OUTPUT_NAME)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(final))

    print("Done ✔")


if __name__ == "__main__":
    main()
