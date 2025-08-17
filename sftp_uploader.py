# sftp_uploader.py
import os
import json
import getpass
import argparse
import logging
import shutil
from pathlib import Path, PurePosixPath
from typing import List, Optional
from cryptography.fernet import Fernet
import paramiko
from tqdm import tqdm
from colorama import init, Fore

init(autoreset=True)

CONFIG_FILE = "sftp_config.json"
KEY_FILE = "sftp_key.key"
LOG_FILE = "sftp_upload.log"
EXCLUDED_FILES = {CONFIG_FILE, KEY_FILE, LOG_FILE}

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ---------- tiny helpers ----------
def info(msg): print(f"{Fore.CYAN}ℹ {msg}")
def ok(msg): print(f"{Fore.GREEN}✅ {msg}")
def warn(msg): print(f"{Fore.YELLOW}⚠ {msg}")
def err(msg): print(f"{Fore.RED}❌ {msg}")

def truncate(name: str, width: int = 60) -> str:
    return name if len(name) <= width else "…" + name[-(width - 1):]

# ---------- key / config ----------
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_password(password, key):
    return Fernet(key).encrypt(password.encode()).decode()

def decrypt_password(token, key):
    return Fernet(key).decrypt(token.encode()).decode()

def save_config(cfg, key):
    """Save config. Only persists password if save_password is True."""
    data = cfg.copy()
    if data.get("save_password", True):
        if isinstance(data.get("password"), str):
            data["password"] = encrypt_password(data["password"], key)
    else:
        data.pop("password", None)
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)
    logging.info("Configuration saved.")

def load_config(key):
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        data = json.load(f)
    # defaults for new fields
    data.setdefault("recursive", False)
    data.setdefault("skip_existing", True)     # default to skipping
    data.setdefault("save_password", True)     # default to saving password (as before)
    # decrypt if present and saving enabled
    if data.get("save_password") and "password" in data:
        try:
            data["password"] = decrypt_password(data["password"], key)
        except Exception:
            # corrupted or key rotated; force prompt on next run
            data.pop("password", None)
            warn("Saved password could not be decrypted; will prompt at runtime.")
    else:
        data.pop("password", None)
    logging.info("Configuration loaded.")
    return data

def prompt_config():
    info("Enter SFTP settings:")
    host = input("Host: ")
    port = int(input("Port (default 22): ") or 22)
    username = input("Username: ")
    # ask whether to save password first, so we know if we prompt now
    sp_in = input("Save password (encrypted) to config? (Y/n): ").strip().lower()
    save_password = (sp_in == "" or sp_in in ("y", "yes", "true", "1"))
    if save_password:
        password = getpass.getpass("Password (will be saved encrypted): ")
    else:
        password = None  # will prompt at runtime
    remote_dir = input("Remote directory (e.g., /uploads): ").strip() or "/"
    exts = input("File extensions (comma-separated, e.g., txt,jpg,png): ")
    extensions = [e.strip().lower().lstrip(".") for e in exts.split(",") if e.strip()]
    rec_in = input("Include subfolders? (y/N): ").strip().lower()
    recursive = rec_in in ("y", "yes", "true", "1")
    skip_in = input("Skip files that already exist on remote (same size)? (Y/n): ").strip().lower()
    skip_existing = (skip_in == "" or skip_in in ("y", "yes", "true", "1"))
    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,          # may be None if not saved
        "remote_dir": remote_dir,
        "extensions": extensions,
        "recursive": recursive,
        "skip_existing": skip_existing,
        "save_password": save_password
    }

# ---------- files ----------
def collect_files(extensions: List[str], recursive: bool) -> List[Path]:
    exts = [e.lower().lstrip(".") for e in extensions]
    base = Path(".").resolve()
    files: List[Path] = []
    if recursive:
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            if p.name in EXCLUDED_FILES:
                continue
            if any(p.name.lower().endswith("." + e) for e in exts):
                files.append(p)
    else:
        for p in base.iterdir():
            if not p.is_file():
                continue
            if p.name in EXCLUDED_FILES:
                continue
            if any(p.name.lower().endswith("." + e) for e in exts):
                files.append(p)
    return sorted(files, key=lambda x: str(x.relative_to(base)).lower())

# ---------- remote helpers ----------
def sftp_remote_size(sftp: paramiko.SFTPClient, path: str) -> Optional[int]:
    try:
        st = sftp.stat(path)
        return getattr(st, "st_size", None)
    except IOError:
        return None

def sftp_mkdir_p(sftp: paramiko.SFTPClient, dir_path: str):
    path = PurePosixPath(dir_path)
    parts = path.parts
    if not parts:
        return
    curr = PurePosixPath("/")
    if str(path).startswith("/"):
        start_idx = 1
    else:
        curr = PurePosixPath(".")
        start_idx = 0
    for i in range(start_idx, len(parts)):
        curr = curr / parts[i]
        p = str(curr)
        try:
            sftp.stat(p)
        except IOError:
            sftp.mkdir(p)

# ---------- password resolution ----------
def resolve_runtime_password(cfg: dict, key, args) -> str:
    """
    Decide what password to use for this run, based on:
    - args.ask_password forces prompt
    - args.set_password prompts and optionally saves if save_password=True
    - cfg.save_password & cfg.password if available
    - otherwise prompt
    """
    # --set-password: prompt to set new password
    if args.set_password:
        newpwd = getpass.getpass("Set new password: ")
        if cfg.get("save_password", True):
            cfg["password"] = newpwd
            save_config(cfg, key)
            ok("Password updated and saved.")
        else:
            ok("Password set for this run (not saved).")
        return newpwd

    # --ask-password: prompt for this run, do not change config
    if args.ask_password:
        return getpass.getpass("Password: ")

    # saved password path
    if cfg.get("save_password", True) and isinstance(cfg.get("password"), str):
        return cfg["password"]

    # otherwise prompt
    return getpass.getpass("Password: ")

# ---------- upload ----------
def upload_files(files: List[Path], cfg: dict, password: str):
    host, port, user, remote_root, recursive, skip_existing = (
        cfg["host"], cfg["port"], cfg["username"],
        cfg["remote_dir"], cfg["recursive"], cfg["skip_existing"]
    )

    base = Path(".").resolve()

    transport = paramiko.Transport((host, port))
    try:
        transport.connect(username=user, password=password)
    except Exception as e:
        err(f"Connection failed: {e}")
        return
    sftp = paramiko.SFTPClient.from_transport(transport)

    try:
        sftp.chdir(remote_root)
    except IOError:
        sftp_mkdir_p(sftp, remote_root)
        sftp.chdir(remote_root)

    total_size = sum(f.stat().st_size for f in files)
    term_width = shutil.get_terminal_size((100, 20)).columns
    bar_format = "{l_bar}{bar}| {n_fmt}/{total_fmt} {unit} [{rate_fmt} • {elapsed}<{remaining}]"

    with tqdm(
        total=total_size, unit="B", unit_scale=True, unit_divisor=1024,
        desc="📦 Total", ncols=term_width, bar_format=bar_format
    ) as total_bar:

        for local_path in files:
            rel_path = local_path.relative_to(base)
            remote_path = PurePosixPath(remote_root) / PurePosixPath(rel_path.as_posix())
            remote_dir = str(remote_path.parent)
            sftp_mkdir_p(sftp, remote_dir)

            local_size = local_path.stat().st_size
            remote_size = sftp_remote_size(sftp, str(remote_path))

            # Skip only if remote exists AND sizes match
            if skip_existing and remote_size is not None and remote_size == local_size:
                total_bar.update(local_size)
                msg = f"Skipped (exists same size): {rel_path}"
                tqdm.write(msg)
                logging.info(msg)
                continue

            with tqdm(
                total=local_size, unit="B", unit_scale=True, unit_divisor=1024,
                desc=f"📤 {truncate(str(rel_path))}",
                ncols=term_width, bar_format=bar_format, leave=False
            ) as file_bar:
                with local_path.open("rb") as fin, sftp.file(str(remote_path), "wb") as fout:
                    while True:
                        chunk = fin.read(32768)
                        if not chunk:
                            break
                        fout.write(chunk)
                        file_bar.update(len(chunk))
                        total_bar.update(len(chunk))

            logging.info(f"Uploaded {rel_path} -> {remote_path}")

    sftp.close()
    transport.close()
    ok("Upload complete.")

# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(description="SFTP uploader")
    parser.add_argument("--configure", action="store_true", help="Run interactive config setup")
    parser.add_argument("--extensions", type=str, help="Override extensions this run (e.g., jpg,png)")
    parser.add_argument("--dry-run", action="store_true", help="List matching files, do not upload")
    parser.add_argument("--upload", action="store_true", help="Start upload (default if no args)")
    parser.add_argument("--recursive", action="store_true", help="Include subfolders for this run")
    parser.add_argument("--no-recursive", action="store_true", help="Force no subfolders for this run")
    parser.add_argument("--skip-existing", action="store_true", help="Skip existing files (same size) this run")
    parser.add_argument("--no-skip-existing", action="store_true", help="Do not skip existing files this run")
    # NEW password behavior flags
    parser.add_argument("--save-password", action="store_true", help="Persist password (encrypted) in config")
    parser.add_argument("--no-save-password", action="store_true", help="Do not store password; prompt each run")
    parser.add_argument("--ask-password", action="store_true", help="Prompt for password for this run")
    parser.add_argument("--set-password", action="store_true", help="Set a new password (saved only if save_password=True)")
    parser.add_argument("--reset", action="store_true", help="Delete saved config and key, then exit")
    args = parser.parse_args()

    key = load_key()

    if args.reset:
        if os.path.exists(CONFIG_FILE): os.remove(CONFIG_FILE)
        if os.path.exists(KEY_FILE): os.remove(KEY_FILE)
        ok("Reset complete.")
        return

    # Configure if requested or no config exists
    if args.configure or not os.path.exists(CONFIG_FILE):
        cfg = prompt_config()
        save_config(cfg, key)
        ok("Configuration saved.")
    cfg = load_config(key)
    if cfg is None:
        cfg = prompt_config()
        save_config(cfg, key)
        ok("Configuration saved.")
        cfg = load_config(key)

    # Overrides
    if args.extensions:
        cfg["extensions"] = [e.strip().lower().lstrip(".") for e in args.extensions.split(",") if e.strip()]
    if args.recursive:
        cfg["recursive"] = True
    if args.no_recursive:
        cfg["recursive"] = False
    if args.skip_existing:
        cfg["skip_existing"] = True
    if args.no_skip_existing:
        cfg["skip_existing"] = False
    # Password storage policy overrides
    if args.save_password:
        cfg["save_password"] = True
        # if we have a decrypted cfg["password"] missing, user may set with --set-password or we’ll prompt once and save now
    if args.no_save_password:
        cfg["save_password"] = False
        # ensure not persisted on next save
        cfg.pop("password", None)

    # Resolve password for this run
    password = resolve_runtime_password(cfg, key, args)

    # If user changed save_password policy, persist config now (without re-prompting)
    # Note: will save or drop password per policy.
    save_config(cfg, key)

    files = collect_files(cfg["extensions"], cfg["recursive"])
    if not files:
        warn(f"No matching files found for: {cfg['extensions']} (recursive={cfg['recursive']})")
        return

    if args.dry_run:
        info(f"Dry run (recursive={cfg['recursive']}, skip_existing={cfg['skip_existing']}, save_password={cfg['save_password']}):")
        base = Path(".").resolve()
        for f in files:
            print(" •", f.relative_to(base))
        return

    # Default: upload when no action flags passed
    should_upload = args.upload or (not args.configure and not args.dry_run and not args.reset and not args.set_password)
    if not should_upload:
        info("Nothing to do. Use --upload or --dry-run (upload runs by default with no args).")
        return

    info(f"Uploading {len(files)} file(s) to {cfg['remote_dir']} on {cfg['host']}:{cfg['port']} "
         f"(recursive={cfg['recursive']}, skip_existing={cfg['skip_existing']}, save_password={cfg['save_password']})")
    upload_files(files, cfg, password)

if __name__ == "__main__":
    main()
