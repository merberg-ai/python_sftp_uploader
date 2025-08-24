# SFTP Uploader CLI

A Python command-line tool to securely upload files via SFTP with progress bars, encryption, persistent configuration, and an optional GUI mode.

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
- **Optional GUI** (`--gui`): simple Tkinter interface for configuration and upload with **Save Settings**, **Upload**, and **Cancel** buttons.

---

## 📦 Installation

1. Clone this repository or copy the scripts.
2. Install dependencies:

For **CLI only**:

```bash
pip install -r requirements.txt
```

For **CLI + GUI**:

```bash
pip install -r requirements-gui.txt
```

Dependencies:

- `paramiko` – SFTP/SSH support  
- `cryptography` – secure password storage  
- `tqdm` – progress bars  
- `colorama` – colored console output  
- `tkinter` (built-in with Python on most platforms)  

---

## 🚀 Usage

Run the **CLI uploader**:

```bash
python sftp_uploader.py
```

Run the **GUI uploader**:

```bash
python sftp_uploader_gui.py --gui
```

Or use the launchers (after unzip):

- **Windows (CLI)**: `run-uploader.bat`  
- **Windows (GUI)**: `run-uploader-gui.bat`  
- **macOS/Linux (CLI)**: `./run-uploader.sh`  
- **macOS/Linux (GUI)**: `./run-uploader-gui.sh`  

### Common CLI Commands

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

- **Password saving**:
  - Always ask:
    ```bash
    python sftp_uploader.py --no-save-password
    ```
  - Save securely (default):
    ```bash
    python sftp_uploader.py --save-password
    ```
  - Prompt for password just this run:
    ```bash
    python sftp_uploader.py --ask-password
    ```
  - Set new password:
    ```bash
    python sftp_uploader.py --set-password
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
