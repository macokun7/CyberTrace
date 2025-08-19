# launch_cybertrace.py — one-file bootstrapper for CyberTrace
from __future__ import annotations
import os, sys, subprocess, shutil, textwrap

HERE = os.path.abspath(os.path.dirname(__file__))
VENV_DIR = os.path.join(HERE, ".venv")

REQ_FILE = os.path.join(HERE, "requirements.txt")
REQUIRED_PKGS = [
    "rich>=13.0",
    "dnspython>=2.6",
    "python-whois>=0.9",
    "PyYAML>=6.0",
]

CYBERTRACE = os.path.join(HERE, "cybertrace.py")

def venv_python(venv_dir: str) -> str:
    if os.name == "nt":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python3")

def run(cmd: list[str], check: bool = True) -> int:
    # Show nice, compact command on Windows double-click too
    print("> " + " ".join(cmd))
    return subprocess.run(cmd, check=check).returncode

def ensure_venv():
    if os.path.isdir(VENV_DIR) and os.path.isfile(venv_python(VENV_DIR)):
        return
    print("[*] Creating virtual environment at .venv ...")
    # Use the same python that launched this script
    run([sys.executable, "-m", "venv", VENV_DIR])

def ensure_requirements():
    py = venv_python(VENV_DIR)
    print("[*] Upgrading pip ...")
    run([py, "-m", "pip", "install", "--upgrade", "pip"], check=True)

    if os.path.isfile(REQ_FILE):
        print("[*] Installing from requirements.txt ...")
        run([py, "-m", "pip", "install", "-r", REQ_FILE], check=True)
    else:
        print("[*] requirements.txt not found — installing minimal set ...")
        run([py, "-m", "pip", "install", *REQUIRED_PKGS], check=True)

def run_cybertrace():
    py = venv_python(VENV_DIR)
    if not os.path.isfile(CYBERTRACE):
        msg = textwrap.dedent(f"""
        [!] Could not find cybertrace.py in:
            {HERE}
        Make sure launch_cybertrace.py is in the same folder as cybertrace.py
        """).strip()
        print(msg)
        pause_and_exit(1)
    print("[*] Launching CyberTrace ...")
    # Run the app and forward its exit code
    code = subprocess.run([py, CYBERTRACE]).returncode
    if code != 0:
        print(f"[!] CyberTrace exited with code {code}.")
    return code

def pause_and_exit(code: int):
    try:
        # Keep the window open when double-clicked
        input("\nPress Enter to close...")
    except Exception:
        pass
    sys.exit(code)

def main():
    try:
        ensure_venv()
        ensure_requirements()
        code = run_cybertrace()
        pause_and_exit(code)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")
        pause_and_exit(e.returncode if isinstance(e.returncode, int) else 1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        pause_and_exit(1)

if __name__ == "__main__":
    main()
