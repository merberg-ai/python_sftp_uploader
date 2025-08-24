#!/usr/bin/env python3
"""
sftp_uploader_gui.py

- Without --gui: delegates to the original CLI script's logic (unchanged behavior).
- With --gui: opens a Tkinter GUI to configure and run uploads.
Now includes: Save Settings, Upload, and Cancel buttons.
"""
import argparse
import threading
import queue
import getpass
from pathlib import Path, PurePosixPath
from typing import List, Optional

import tkinter as tk
from tkinter import ttk, messagebox

# Import original CLI logic (must be in same directory)
import sftp_uploader as cli
import paramiko

EXCLUDED_FILES = {cli.CONFIG_FILE, cli.KEY_FILE, cli.LOG_FILE}

def collect_files_gui(extensions: List[str], recursive: bool) -> List[Path]:
    exts = [e.lower().lstrip(".") for e in extensions]
    base = Path(".").resolve()
    files: List[Path] = []
    if recursive:
        for p in base.rglob("*"):
            if p.is_file() and p.name not in EXCLUDED_FILES and any(p.name.lower().endswith("." + e) for e in exts):
                files.append(p)
    else:
        for p in base.iterdir():
            if p.is_file() and p.name not in EXCLUDED_FILES and any(p.name.lower().endswith("." + e) for e in exts):
                files.append(p)
    return sorted(files, key=lambda x: str(x.relative_to(base)).lower())

def sftp_remote_size(sftp: paramiko.SFTPClient, path: str) -> Optional[int]:
    try:
        st = sftp.stat(path)
        return getattr(st, "st_size", None)
    except Exception:
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
        except Exception:
            sftp.mkdir(p)

class UploaderGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SFTP Uploader")
        self.geometry("760x560")
        self.resizable(True, True)

        self.msg_queue = queue.Queue()
        self.stop_flag = threading.Event()
        self.worker = None

        self._build_form()
        self._build_progress()
        self._build_buttons()
        self._poll_messages()

        try:
            key = cli.load_key()
            cfg = cli.load_config(key)
            if cfg:
                self._apply_cfg_to_form(cfg)
        except Exception:
            pass

    def _build_form(self):
        frm = ttk.LabelFrame(self, text="Connection & Options")
        frm.pack(fill="x", padx=10, pady=10)

        row = 0
        ttk.Label(frm, text="Host").grid(row=row, column=0, sticky="e", padx=6, pady=4)
        self.host_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.host_var, width=40).grid(row=row, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(frm, text="Port").grid(row=row, column=2, sticky="e", padx=6, pady=4)
        self.port_var = tk.StringVar(value="22")
        ttk.Entry(frm, textvariable=self.port_var, width=10).grid(row=row, column=3, sticky="w", padx=6, pady=4)

        row += 1
        ttk.Label(frm, text="Username").grid(row=row, column=0, sticky="e", padx=6, pady=4)
        self.user_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.user_var, width=40).grid(row=row, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(frm, text="Password").grid(row=row, column=2, sticky="e", padx=6, pady=4)
        self.pass_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.pass_var, width=20, show="•").grid(row=row, column=3, sticky="w", padx=6, pady=4)

        row += 1
        ttk.Label(frm, text="Remote dir").grid(row=row, column=0, sticky="e", padx=6, pady=4)
        self.remote_var = tk.StringVar(value="/uploads")
        ttk.Entry(frm, textvariable=self.remote_var, width=40).grid(row=row, column=1, sticky="w", padx=6, pady=4)

        ttk.Label(frm, text="Extensions").grid(row=row, column=2, sticky="e", padx=6, pady=4)
        self.exts_var = tk.StringVar(value="txt,jpg,png")
        ttk.Entry(frm, textvariable=self.exts_var, width=20).grid(row=row, column=3, sticky="w", padx=6, pady=4)

        row += 1
        self.recursive_var = tk.BooleanVar(value=False)
        self.skip_var = tk.BooleanVar(value=True)
        self.savepw_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="Recursive (include subfolders)", variable=self.recursive_var).grid(row=row, column=0, columnspan=2, sticky="w", padx=6, pady=2)
        ttk.Checkbutton(frm, text="Skip existing files (same size)", variable=self.skip_var).grid(row=row, column=2, columnspan=2, sticky="w", padx=6, pady=2)

        row += 1
        ttk.Checkbutton(frm, text="Save password (encrypted)", variable=self.savepw_var).grid(row=row, column=0, columnspan=2, sticky="w", padx=6, pady=2)

    def _build_progress(self):
        box = ttk.LabelFrame(self, text="Progress")
        box.pack(fill="x", padx=10, pady=6)

        self.total_label = ttk.Label(box, text="Total: 0 / 0")
        self.total_label.pack(anchor="w", padx=8, pady=4)
        self.total_bar = ttk.Progressbar(box, orient="horizontal", mode="determinate")
        self.total_bar.pack(fill="x", padx=8, pady=4)

        self.file_label = ttk.Label(box, text="File: (idle)")
        self.file_label.pack(anchor="w", padx=8, pady=4)
        self.file_bar = ttk.Progressbar(box, orient="horizontal", mode="determinate")
        self.file_bar.pack(fill="x", padx=8, pady=4)

        self.log = tk.Text(self, height=12)
        self.log.pack(fill="both", expand=True, padx=10, pady=6)
        self.log.configure(state="disabled")

    def _build_buttons(self):
        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=10, pady=10)
        ttk.Button(btns, text="Load Config", command=self.on_load_config).pack(side="left")
        ttk.Button(btns, text="Save Settings", command=self.on_save_config).pack(side="left", padx=6)
        ttk.Button(btns, text="Upload", command=self.on_start).pack(side="right")
        ttk.Button(btns, text="Cancel", command=self.on_cancel).pack(side="right", padx=6)
        ttk.Button(btns, text="Dry Run", command=self.on_dry_run).pack(side="right", padx=6)

    def _poll_messages(self):
        try:
            while True:
                msg = self.log_queue_get_nowait()
                self.log.configure(state="normal")
                self.log.insert("end", msg + "\n")
                self.log.see("end")
                self.log.configure(state="disabled")
        except Exception:
            pass
        self.after(80, self._poll_messages)

    def log_queue_get_nowait(self):
        try:
            return self.msg_queue.get_nowait()
        except queue.Empty:
            raise Exception

    def append_log(self, text: str):
        self.msg_queue.put(text)

    def _apply_cfg_to_form(self, cfg: dict):
        self.host_var.set(cfg.get("host", ""))
        self.port_var.set(str(cfg.get("port", 22)))
        self.user_var.set(cfg.get("username", ""))
        self.remote_var.set(cfg.get("remote_dir", "/"))
        self.exts_var.set(",".join(cfg.get("extensions", [])))
        self.recursive_var.set(bool(cfg.get("recursive", False)))
        self.skip_var.set(bool(cfg.get("skip_existing", True)))
        self.savepw_var.set(bool(cfg.get("save_password", True)))

    def _read_form_to_cfg(self) -> dict:
        exts = [e.strip().lower().lstrip(".") for e in self.exts_var.get().split(",") if e.strip()]
        return {
            "host": self.host_var.get().strip(),
            "port": int(self.port_var.get() or 22),
            "username": self.user_var.get().strip(),
            "password": self.pass_var.get().strip() or None,
            "remote_dir": self.remote_var.get().strip() or "/",
            "extensions": exts,
            "recursive": self.recursive_var.get(),
            "skip_existing": self.skip_var.get(),
            "save_password": self.savepw_var.get(),
        }

    def on_load_config(self):
        try:
            key = cli.load_key()
            cfg = cli.load_config(key)
            if cfg:
                self._apply_cfg_to_form(cfg)
                self.append_log("Loaded configuration.")
            else:
                messagebox.showinfo("Config", "No configuration found yet.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration:\n{e}")

    def on_save_config(self):
        cfg = self._read_form_to_cfg()
        key = cli.load_key()
        try:
            cli.save_config(cfg, key)
            self.append_log("Saved configuration.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration:\n{e}")

    def on_dry_run(self):
        cfg = self._read_form_to_cfg()
        files = collect_files_gui(cfg["extensions"], cfg["recursive"])
        if not files:
            messagebox.showinfo("Dry Run", "No matching files found.")
            return
        self.append_log(f"Dry run: {len(files)} file(s) would be uploaded:")
        base = Path(".").resolve()
        for f in files:
            self.append_log(f" • {f.relative_to(base)}")

    def on_start(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Upload", "An upload is already running.")
            return

        self.stop_flag.clear()
        cfg = self._read_form_to_cfg()
        if not cfg["host"] or not cfg["username"]:
            messagebox.showwarning("Missing", "Host and Username are required.")
            return

        key = cli.load_key()
        if cfg["save_password"] and cfg.get("password"):
            try:
                cli.save_config(cfg, key)
            except Exception:
                pass

        password = None
        if cfg["save_password"]:
            try:
                saved = cli.load_config(key)
                if saved and isinstance(saved.get("password"), str):
                    password = saved["password"]
            except Exception:
                password = None
        if not password:
            password = cfg.get("password") or getpass.getpass("Password: ")

        self.worker = threading.Thread(target=self._run_upload_worker, args=(cfg, password), daemon=True)
        self.worker.start()

    def on_cancel(self):
        if self.worker and self.worker.is_alive():
            self.stop_flag.set()
            self.append_log("⚠ Cancel requested. Upload will stop soon.")
        else:
            self.append_log("No active upload to cancel.")

    def _run_upload_worker(self, cfg: dict, password: str):
        try:
            files = collect_files_gui(cfg["extensions"], cfg["recursive"])
            if not files:
                self.append_log("No matching files found.")
                return

            total_size = sum(p.stat().st_size for p in files)
            self.total_bar.configure(maximum=max(1, total_size))
            self.total_bar["value"] = 0
            self.total_label.config(text=f"Total: 0 / {self._fmt_bytes(total_size)}")

            transport = paramiko.Transport((cfg["host"], int(cfg["port"])))
            transport.connect(username=cfg["username"], password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            try:
                sftp.chdir(cfg["remote_dir"])
            except Exception:
                sftp_mkdir_p(sftp, cfg["remote_dir"])
                sftp.chdir(cfg["remote_dir"])

            base = Path(".").resolve()
            total_done = 0

            for local_path in files:
                if self.stop_flag.is_set():
                    self.append_log("Upload cancelled.")
                    break

                rel_path = local_path.relative_to(base)
                remote_path = PurePosixPath(cfg["remote_dir"]) / PurePosixPath(rel_path.as_posix())
                sftp_mkdir_p(sftp, str(remote_path.parent))

                local_size = local_path.stat().st_size
                self.file_bar.configure(maximum=max(1, local_size))
                self.file_bar["value"] = 0
                self.file_label.config(text=f"File: {rel_path} (0 / {self._fmt_bytes(local_size)})")
                self.update_idletasks()

                if cfg.get("skip_existing", True):
                    rsize = sftp_remote_size(sftp, str(remote_path))
                    if rsize is not None and rsize == local_size:
                        total_done += local_size
                        self.total_bar["value"] = total_done
                        self.total_label.config(text=f"Total: {self._fmt_bytes(total_done)} / {self._fmt_bytes(total_size)}")
                        self.append_log(f"Skipped (exists same size): {rel_path}")
                        continue

                sent = 0
                with local_path.open("rb") as fin, sftp.file(str(remote_path), "wb") as fout:
                    while True:
                        if self.stop_flag.is_set():
                            self.append_log("Upload cancelled during file transfer.")
                            break
                        chunk = fin.read(32768)
                        if not chunk:
                            break
                        fout.write(chunk)
                        sent += len(chunk)
                        total_done += len(chunk)
                        self.file_bar["value"] = sent
                        self.file_label.config(text=f"File: {rel_path} ({self._fmt_bytes(sent)} / {self._fmt_bytes(local_size)})")
                        self.total_bar["value"] = total_done
                        self.total_label.config(text=f"Total: {self._fmt_bytes(total_done)} / {self._fmt_bytes(total_size)}")
                        self.update_idletasks()

                self.append_log(f"Uploaded: {rel_path}")

            sftp.close()
            transport.close()
            if self.stop_flag.is_set():
                self.append_log("⏹ Upload stopped by user.")
                messagebox.showinfo("Stopped", "Upload cancelled.")
            else:
                self.append_log("✅ Upload complete.")
                messagebox.showinfo("Done", "Upload complete.")

        except Exception as e:
            self.append_log(f"❌ Error: {e}")
            messagebox.showerror("Error", str(e))

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
            n /= 1024
        return f"{n:.2f} PB"

def main():
    parser = argparse.ArgumentParser(description="SFTP Uploader with optional GUI")
    parser.add_argument("--gui", action="store_true", help="Open the GUI (otherwise behaves like the CLI script)")
    args, _ = parser.parse_known_args()

    if not args.gui:
        return cli.main()

    app = UploaderGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
