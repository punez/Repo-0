import requests
import base64

INPUT_FILE = "inputs.txt"
OUTPUT_FILE = "output.txt"
TIMEOUT = 10

def fetch(url):
    try:
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.text.strip()
    except:
        pass
    return None

def try_decode(text):
    try:
        if not text.startswith(("vmess://", "vless://", "trojan://")):
            return base64.b64decode(text).decode("utf-8")
    except:
        pass
    return text

def extract_configs(text):
    lines = text.split("\n")
    valid = []
    for l in lines:
        l = l.strip()
        if l.startswith(("vmess://","vless://","trojan://","ss://","ssr://","hy2://","tuic://")):
            valid.append(l)
    return valid

def main():
    final = []

    with open(INPUT_FILE) as f:
        sources = [line.strip() for line in f if line.strip()]

    for url in sources:
        data = fetch(url)
        if not data:
            continue
        data = try_decode(data)
        configs = extract_configs(data)
        final.extend(configs)

    final = list(dict.fromkeys(final))  # dedup ساده

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final))

if __name__ == "__main__":
    main()
