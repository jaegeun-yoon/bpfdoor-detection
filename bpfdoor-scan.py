import os
import hashlib

# BPF 악성 파일 정보 목록
malicious_files = [
    {
        "name": "hpasmmld",
        "path": "/usr/bin/hpasmmld",
        "size": 2265 * 1024,
        "sha256": "c7f693f7f85b01a8c0e561bd369845f40bff423b0743c7aa0f4c323d9133b5d4"
    },
    {
        "name": "smartadm",
        "size": 2067 * 1024,
        "sha256": "3f6f108db37d18519f47c5e4182e5e33cc795564f286ae770aa03372133d15c4"
    },
    {
        "name": "hald-addon-volume",
        "size": 2071 * 1024,
        "sha256": "95fd8a70c4b18a9a669fec6eb82dac0ba6a9236ac42a5ecde270330b66f51595"
    },
    {
        "name": "dbus-srv-bin.txt",
        "size": 34 * 1024,
        "sha256": "aa779e83ff5271d3f2d270eaed16751a109eb722fca61465d86317e03bbf49e4"
    },
    {
        "name": "dbus-srv",
        "size" : 34 * 1024,
        "sha256": "925ec4e617adc81d6fcee60876f6b878e0313a11f25526179716a90c3b743173"
    },
    {
        "name": "",
        "size" : 34 * 1024,
        "sha256": "925ec4e617adc81d6fcee60876f6b878e0313a11f25526179716a90c3b743173"
    },
    {
        "name": "inode262394",
        "size" : 28 * 1024,
        "sha256": "29564c19a15b06dd5be2a73d7543288f5b4e9e6668bbd5e48d3093fb6ddf1fdb"
    },
    {
        "name": "dbus-srv",
        "size" : 34 * 1024,
        "sha256": "be7d952d37812b7482c1d770433a499372fde7254981ce2e8e974a67f6a088b5"
    },
    {
        "name": "dbus-srv",
        "size" : 34 * 1024,
        "sha256": "027b1fed1b8213b86d8faebf51879ccc9b1afec7176e31354fbac695e8daf416"
    },
    {
        "name": "dbus-srv",
        "size" : 32 * 1024,
        "sha256": "a2ea82b3f5be30916c4a00a7759aa6ec1ae6ddadc4d82b3481640d8f6a325d59"
    },
    {
        "name": "File_in_Inode_#1900667",
        "size" : 28 * 1024,
        "sha256": "e04586672874685b019e9120fcd1509d68af6f9bc513e739575fc73edefd511d"
    },
    {
        "name": "gm",
        "size" : 2063 * 1024,
        "sha256": "adfdd11d69f4e971c87ca5b2073682d90118c0b3a3a9f5fbbda872ab1fb335c6"
    
    },
    {
        "name": "rad",
        "size" : 22 * 1024,
        "sha256": "7c39f3c3120e35b8ab89181f191f01e2556ca558475a2803cb1f02c05c830423"
    },
]

# SHA256 해시 계산 함수
def compute_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None

# 탐지 함수
def scan_directory(base_dir):
    for root, dirs, files in os.walk(base_dir, onerror=lambda e: None):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                file_size = os.path.getsize(filepath)
                file_hash = compute_sha256(filepath)
                for entry in malicious_files:
                    if file_hash == entry["sha256"]: # file_size == entry["size"]
                        print(f"[!] MALICIOUS FILE DETECTED: {filepath} (matches {entry['name']}), size: {entry["size"]}")
            except:
                pass  # 오류 무시 (e.g., 권한 없음, 심볼릭 링크 깨짐 등)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="BPFdoor hash-based scanner (quiet mode)")
    parser.add_argument("path", help="Path to scan (file or directory)")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        scan_directory(args.path)
    elif os.path.isfile(args.path):
        scan_directory(os.path.dirname(args.path))
    else:
        print(f"[!] Invalid path: {args.path}")
