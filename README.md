<h1>THIS IS MY PERSONAL PROJECT FOR PERSONAL USE. DO NOT USE IN A PRODUCTION ENVIRONMENT!</h1>

# SFTP Uploader CLI

A Python command-line tool to securely upload files via SFTP with progress bars, encryption, and persistent configuration.

## ✨ Features

- Upload files with specified extensions from the current folder (and optionally subfolders).
- Dual progress bars: one for **total progress** and one for the **current file**.
- Configurable settings:
  - Host, port, username
  - Remote directory
  - File extensions (comma-separated)
  - Recursive uploads (include subfolders or not)
  - Skip existing files (default: enabled, compares file size)
  - Save password (encrypted) or prompt every run
- Config file and encryption key stored locally (`sftp_config.json` + `sftp_key.key`).
- Logs uploads and skips to `sftp_upload.log`.
- Colorful, user-friendly console output.
- Command-line arguments for flexible control.

---

## 📦 Installation

1. Clone this repository or copy the script.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

Dependencies:

- `paramiko` – SFTP/SSH support
- `cryptography` – secure password storage
- `tqdm` – progress bars
- `colorama` – colored console output

---

## 🚀 Usage

Run the script:

```bash
python sftp_uploader.py
```

On first run, it will ask you for connection info and file extensions, then save them securely.

### Common Commands

- **Configure interactively**:
  ```bash
  python sftp_uploader.py --configure
  ```

- **Upload (default when no args given)**:
  ```bash
  python sftp_uploader.py
  ```

- **Dry run (list files, no upload)**:
  ```bash
  python sftp_uploader.py --dry-run
  ```

- **Recursive mode (include subfolders)**:
  ```bash
  python sftp_uploader.py --recursive
  ```

- **Force non-recursive**:
  ```bash
  python sftp_uploader.py --no-recursive
  ```

- **Skip existing files (same size) [default]**:
  ```bash
  python sftp_uploader.py --skip-existing
  ```

- **Do NOT skip existing files (overwrite always)**:
  ```bash
  python sftp_uploader.py --no-skip-existing
  ```

- **Override extensions for this run**:
  ```bash
  python sftp_uploader.py --extensions=jpg,png,gif
  ```

- **Change password saving behavior**:
  - Always ask password:
    ```bash
    python sftp_uploader.py --no-save-password
    ```
  - Save password securely (default):
    ```bash
    python sftp_uploader.py --save-password
    ```

- **Reset (delete config and key)**:
  ```bash
  python sftp_uploader.py --reset
  ```

---

## 📁 Files Created

- `sftp_config.json` – stores config (with encrypted password if enabled).
- `sftp_key.key` – Fernet encryption key for your password.
- `sftp_upload.log` – logs uploads, skips, and errors.

> ⚠️ These files are excluded from upload automatically.

---

## 📝 License

MIT License. Do whatever you want, just don’t blame me if zombies eat your files. 🧟
