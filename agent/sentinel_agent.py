#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║                  SentinelLog Linux Agent                        ║
║                                                                  ║
║  รันบนเซิร์ฟเวอร์ Linux เพื่อ:                                    ║
║    1. อ่าน Nginx access log แล้วส่งเป็น batch ไปยัง Backend       ║
║    2. Poll คำสั่งจาก Backend (block IP, unblock, reload nginx)   ║
║    3. Execute คำสั่งและรายงานผลกลับ                               ║
║    4. ส่ง Heartbeat เพื่อแจ้งว่ายังทำงานอยู่                      ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python3 sentinel_agent.py --register       # ลงทะเบียนครั้งแรก
    python3 sentinel_agent.py                  # รัน agent ปกติ
    python3 sentinel_agent.py --test-connection # ทดสอบการเชื่อมต่อ
"""

import os
import sys
import json
import time
import uuid
import socket
import logging
import argparse
import subprocess
import threading
import base64
import re
import platform
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

try:
    import requests
    from dotenv import load_dotenv
except ImportError:
    print("[ERROR] Missing dependencies. Please run: pip3 install requests python-dotenv")
    sys.exit(1)

# ─────────────────────────── Config ───────────────────────────

BASE_DIR = Path(__file__).parent.resolve()
ENV_FILE = BASE_DIR / ".env"
load_dotenv(ENV_FILE)

# Backend
BACKEND_URL: str = os.getenv("BACKEND_URL", "http://localhost:3000")
AGENT_ID: str = os.getenv("AGENT_ID", "")            # UUID จาก register
AGENT_API_KEY: str = os.getenv("AGENT_API_KEY", "")  # API key จาก register
AGENT_REGISTER_SECRET: str = os.getenv("AGENT_REGISTER_SECRET", "")

# Nginx
NGINX_LOG_PATH: str = os.getenv("NGINX_LOG_PATH", "/var/log/nginx/access.log")
NGINX_ERROR_LOG_PATH: str = os.getenv("NGINX_ERROR_LOG_PATH", "/var/log/nginx/error.log")

# Intervals (วินาที)
LOG_BATCH_INTERVAL: int = int(os.getenv("LOG_BATCH_INTERVAL", "30"))  # ส่ง log ทุก 30s
HEARTBEAT_INTERVAL: int = int(os.getenv("HEARTBEAT_INTERVAL", "60"))  # heartbeat ทุก 60s
COMMAND_POLL_INTERVAL: int = int(os.getenv("COMMAND_POLL_INTERVAL", "10"))  # poll commands ทุก 10s
LOG_BATCH_SIZE: int = int(os.getenv("LOG_BATCH_SIZE", "100"))  # สูงสุด 100 log ต่อ batch

# Firewall backend (iptables หรือ ufw)
FIREWALL_BACKEND: str = os.getenv("FIREWALL_BACKEND", "auto")  # auto | iptables | ufw | nftables

# ─────────────────────────── Logger ───────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(BASE_DIR / "sentinel_agent.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("sentinel-agent")

# ─────────────────────────── HTTP Client ───────────────────────────

class BackendClient:
    """HTTP client สำหรับคุยกับ SentinelLog Backend"""

    def __init__(self, base_url: str, agent_id: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "X-Agent-ID": agent_id,
            "X-Agent-Key": api_key,
        })

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def register(self, register_secret: str, hostname: str, ip_address: str,
                 version: str, metadata: dict) -> dict:
        """ลงทะเบียน agent กับ backend"""
        resp = requests.post(
            self._url("/api/agent/register"),
            json={
                "agent_id": AGENT_ID or str(uuid.uuid4()),
                "hostname": hostname,
                "ip_address": ip_address,
                "version": version,
                "metadata": metadata,
                "secret": register_secret,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def heartbeat(self, ip_address: str) -> bool:
        """ส่ง heartbeat"""
        try:
            resp = self.session.post(
                self._url("/api/agent/heartbeat"),
                json={"ip_address": ip_address},
                timeout=10,
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            log.warning(f"Heartbeat failed: {e}")
            return False

    def send_logs_batch(self, logs: list) -> dict:
        """ส่ง log batch ไปยัง backend"""
        resp = self.session.post(
            self._url("/api/webhook/nginx/batch"),
            json={"logs": logs},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()

    def poll_commands(self) -> List[dict]:
        """ดึง pending commands"""
        try:
            resp = self.session.get(
                self._url("/api/agent/commands"),
                params={"limit": 10},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json().get("data", [])
        except Exception as e:
            log.warning(f"Poll commands failed: {e}")
            return []

    def report_result(self, command_id: int, success: bool,
                      output: str = "", error: str = "") -> bool:
        """รายงานผลการรัน command"""
        try:
            resp = self.session.post(
                self._url(f"/api/agent/commands/{command_id}/result"),
                json={"success": success, "output": output, "error": error},
                timeout=10,
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            log.warning(f"Report result failed: {e}")
            return False


# ─────────────────────────── Firewall Manager ───────────────────────────

class FirewallManager:
    """จัดการ IP blocking ผ่าน iptables / ufw / nftables"""

    def __init__(self, backend: str = "auto"):
        self.backend = self._detect_backend(backend)
        log.info(f"🔥 Firewall backend: {self.backend}")

    def _detect_backend(self, backend: str) -> str:
        if backend != "auto":
            return backend
        # ลอง detect อัตโนมัติ
        for tool in ["ufw", "nftables", "iptables"]:
            if self._cmd_exists(tool):
                return tool
        return "iptables"  # fallback

    @staticmethod
    def _cmd_exists(cmd: str) -> bool:
        return subprocess.run(
            ["which", cmd], capture_output=True
        ).returncode == 0

    @staticmethod
    def _run(cmd: list, timeout: int = 15) -> tuple[bool, str, str]:
        """รัน shell command แล้วคืน (success, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

    def block_ip(self, ip: str, duration_seconds: int = 3600, reason: str = "") -> tuple[bool, str]:
        """Block IP address"""
        if not self._validate_ip(ip):
            return False, f"Invalid IP: {ip}"

        log.info(f"🚫 Blocking IP: {ip} (duration: {duration_seconds}s) reason: {reason}")

        if self.backend == "ufw":
            ok, out, err = self._run(["ufw", "insert", "1", "deny", "from", ip, "to", "any"])
        elif self.backend == "nftables":
            ok, out, err = self._run([
                "nft", "add", "element", "inet", "filter", "blacklist", f"{{ {ip} }}"
            ])
        else:  # iptables
            ok, out, err = self._run([
                "iptables", "-I", "INPUT", "1",
                "-s", ip, "-j", "DROP",
                "-m", "comment", "--comment", f"sentinel:{reason[:50]}"
            ])

        if ok:
            log.info(f"✅ Blocked: {ip}")
            # Schedule auto-unblock ถ้า duration ไม่ใช่ 0 (permanent)
            if duration_seconds > 0:
                threading.Timer(
                    duration_seconds,
                    lambda: self.unblock_ip(ip)
                ).start()
                log.info(f"⏰ Auto-unblock scheduled in {duration_seconds}s for {ip}")
        else:
            log.error(f"❌ Block failed: {ip} — {err}")

        return ok, out or err

    def unblock_ip(self, ip: str) -> tuple[bool, str]:
        """Unblock IP address"""
        if not self._validate_ip(ip):
            return False, f"Invalid IP: {ip}"

        log.info(f"✅ Unblocking IP: {ip}")

        if self.backend == "ufw":
            ok, out, err = self._run(["ufw", "delete", "deny", "from", ip, "to", "any"])
        elif self.backend == "nftables":
            ok, out, err = self._run([
                "nft", "delete", "element", "inet", "filter", "blacklist", f"{{ {ip} }}"
            ])
        else:  # iptables
            # ลบทุก rule ที่ match IP นี้
            ok, out, err = self._run([
                "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
            ])
            # อาจมีหลาย rule — ลบซ้ำจนหมด
            while ok:
                ok, out, err = self._run([
                    "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"
                ])
            ok = True  # ถือว่า OK ถ้า loop หมดแล้ว

        return ok, out or err

    def is_blocked(self, ip: str) -> bool:
        """เช็คว่า IP ถูก block อยู่หรือเปล่า"""
        if not self._validate_ip(ip):
            return False
        if self.backend == "ufw":
            ok, out, _ = self._run(["ufw", "status"])
            return ip in out
        else:  # iptables / nftables
            ok, out, _ = self._run(["iptables", "-L", "INPUT", "-n"])
            return ip in out

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        # Basic IPv4 + IPv6 validation
        ipv4 = re.match(r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$", ip)
        ipv6 = re.match(r"^([0-9a-fA-F:]+)(/\d{1,3})?$", ip)
        return bool(ipv4 or ipv6)


# ─────────────────────────── Nginx Log Reader ───────────────────────────

class NginxLogReader:
    """อ่าน Nginx access.log แบบ tail -f แล้วรวบรวมเป็น batch"""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self._buffer: List[str] = []
        self._lock = threading.Lock()
        self._pos: int = self._get_file_size()

    def _get_file_size(self) -> int:
        try:
            return os.path.getsize(self.log_path)
        except OSError:
            return 0

    def read_new_lines(self) -> List[str]:
        """อ่าน log ใหม่ที่เพิ่มเข้ามาตั้งแต่ครั้งล่าสุด"""
        lines = []
        try:
            current_size = os.path.getsize(self.log_path)

            # Log rotation detection
            if current_size < self._pos:
                log.info("📂 Log rotation detected, resetting position")
                self._pos = 0

            if current_size == self._pos:
                return []

            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._pos)
                new_lines = f.readlines()
                self._pos = f.tell()

            lines = [line.rstrip("\n") for line in new_lines if line.strip()]
        except FileNotFoundError:
            log.warning(f"⚠️  Log file not found: {self.log_path}")
        except Exception as e:
            log.error(f"Error reading log file: {e}")

        return lines

    def collect_batch(self) -> List[Dict]:
        """รวบรวม log batch สูงสุด LOG_BATCH_SIZE รายการ"""
        lines = self.read_new_lines()
        if not lines:
            return []

        batch = []
        for line in lines[:LOG_BATCH_SIZE]:
            if line.strip():
                batch.append({"raw_log": line, "source": "nginx"})

        return batch


# ─────────────────────────── Command Executor ───────────────────────────

class CommandExecutor:
    """Execute คำสั่งที่ได้รับจาก Backend"""

    def __init__(self, firewall: FirewallManager):
        self.firewall = firewall

    def execute(self, command: dict) -> tuple[bool, str, str]:
        """
        รัน command แล้วคืน (success, output, error)
        command schema: { id, command_type, payload }
        """
        cmd_type: str = command.get("command_type", "")
        payload: dict = command.get("payload", {})

        log.info(f"⚡ Executing command: {cmd_type} | payload: {json.dumps(payload)}")

        try:
            if cmd_type == "block_ip":
                return self._block_ip(payload)
            elif cmd_type == "unblock_ip":
                return self._unblock_ip(payload)
            elif cmd_type == "reload_nginx":
                return self._reload_nginx()
            elif cmd_type == "run_script":
                return self._run_script(payload)
            else:
                return False, "", f"Unknown command type: {cmd_type}"

        except Exception as e:
            return False, "", str(e)

    def _block_ip(self, payload: dict) -> tuple[bool, str, str]:
        ip = payload.get("ip")
        if not ip:
            return False, "", "Missing 'ip' in payload"
        duration = int(payload.get("duration_seconds", 3600))
        reason = payload.get("reason", "Blocked by SentinelLog")
        ok, msg = self.firewall.block_ip(ip, duration, reason)
        return ok, msg if ok else "", msg if not ok else ""

    def _unblock_ip(self, payload: dict) -> tuple[bool, str, str]:
        ip = payload.get("ip")
        if not ip:
            return False, "", "Missing 'ip' in payload"
        ok, msg = self.firewall.unblock_ip(ip)
        return ok, msg if ok else "", msg if not ok else ""

    def _reload_nginx(self) -> tuple[bool, str, str]:
        log.info("🔄 Reloading Nginx...")
        ok, out, err = FirewallManager._run(["nginx", "-t"])
        if not ok:
            return False, "", f"Nginx config test failed: {err}"
        ok, out, err = FirewallManager._run(["systemctl", "reload", "nginx"])
        if not ok:
            # ลอง signal แทน
            ok, out, err = FirewallManager._run(["nginx", "-s", "reload"])
        return ok, out, err

    def _run_script(self, payload: dict) -> tuple[bool, str, str]:
        """รัน shell script ที่ encode ด้วย base64"""
        script_b64 = payload.get("script_b64")
        if not script_b64:
            return False, "", "Missing 'script_b64' in payload"

        try:
            script = base64.b64decode(script_b64).decode("utf-8")
        except Exception as e:
            return False, "", f"Failed to decode script: {e}"

        # Security: จำกัดขนาด script
        if len(script) > 10_000:
            return False, "", "Script too large (max 10KB)"

        description = payload.get("description", "custom script")
        log.info(f"📜 Running script: {description}")

        # เขียน script ลง temp file แล้วรัน
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/bash\nset -e\n")
            f.write(script)
            tmp_path = f.name

        try:
            os.chmod(tmp_path, 0o700)
            ok, out, err = FirewallManager._run(["bash", tmp_path], timeout=30)
        finally:
            os.unlink(tmp_path)

        return ok, out, err


# ─────────────────────────── Agent Main ───────────────────────────

class SentinelAgent:
    """Main Agent class"""

    VERSION = "1.0.0"

    def __init__(self):
        self.hostname = socket.gethostname()
        self.ip_address = self._get_local_ip()
        self.client = BackendClient(BACKEND_URL, AGENT_ID, AGENT_API_KEY)
        self.firewall = FirewallManager(FIREWALL_BACKEND)
        self.executor = CommandExecutor(self.firewall)
        self.log_reader = NginxLogReader(NGINX_LOG_PATH)
        self._running = False

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "unknown"

    def _get_metadata(self) -> dict:
        """รวบรวม metadata ของ server"""
        nginx_version = ""
        ok, out, _ = FirewallManager._run(["nginx", "-v"])
        if not ok:
            _, nginx_version, _ = FirewallManager._run(["nginx", "-v"])
        else:
            nginx_version = out

        return {
            "os": platform.system(),
            "os_release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "firewall_backend": self.firewall.backend,
            "nginx_log_path": NGINX_LOG_PATH,
            "nginx_version": nginx_version,
            "capabilities": ["block_ip", "unblock_ip", "reload_nginx", "run_script"],
        }

    # ─── Registration ───

    def register(self):
        """ลงทะเบียน agent กับ backend (รันครั้งเดียว)"""
        if not AGENT_REGISTER_SECRET:
            log.error("❌ AGENT_REGISTER_SECRET is not set in .env")
            sys.exit(1)

        agent_id = AGENT_ID or str(uuid.uuid4())
        log.info(f"📝 Registering agent: {self.hostname} (ID: {agent_id})")

        try:
            resp = self.client.register(
                register_secret=AGENT_REGISTER_SECRET,
                hostname=self.hostname,
                ip_address=self.ip_address,
                version=self.VERSION,
                metadata=self._get_metadata(),
            )

            if not resp.get("success"):
                log.error(f"❌ Registration failed: {resp}")
                sys.exit(1)

            data = resp["data"]
            agent_id_returned = data["agent_id"]
            api_key = data["api_key"]

            print("\n" + "=" * 65)
            print("✅  REGISTRATION SUCCESSFUL — SAVE THESE VALUES TO .env")
            print("=" * 65)
            print(f"AGENT_ID={agent_id_returned}")
            print(f"AGENT_API_KEY={api_key}")
            print("=" * 65)
            print("⚠️  The API key will NOT be shown again!\n")

            # Auto-write ลง .env
            self._write_env(agent_id_returned, api_key)
            log.info("✅ .env updated automatically")

        except requests.HTTPError as e:
            log.error(f"❌ HTTP error during registration: {e.response.text}")
            sys.exit(1)
        except Exception as e:
            log.error(f"❌ Registration error: {e}")
            sys.exit(1)

    def _write_env(self, agent_id: str, api_key: str):
        """เขียน AGENT_ID + AGENT_API_KEY ลงไฟล์ .env"""
        lines = []
        if ENV_FILE.exists():
            lines = ENV_FILE.read_text().splitlines()

        # Update หรือ append
        new_lines = []
        found_id = found_key = False
        for line in lines:
            if line.startswith("AGENT_ID="):
                new_lines.append(f"AGENT_ID={agent_id}")
                found_id = True
            elif line.startswith("AGENT_API_KEY="):
                new_lines.append(f"AGENT_API_KEY={api_key}")
                found_key = True
            else:
                new_lines.append(line)

        if not found_id:
            new_lines.append(f"AGENT_ID={agent_id}")
        if not found_key:
            new_lines.append(f"AGENT_API_KEY={api_key}")

        ENV_FILE.write_text("\n".join(new_lines) + "\n")

    # ─── Test Connection ───

    def test_connection(self):
        """ทดสอบการเชื่อมต่อกับ backend"""
        print(f"\n🔌 Testing connection to: {BACKEND_URL}")
        try:
            resp = requests.get(f"{BACKEND_URL}/health", timeout=5)
            resp.raise_for_status()
            data = resp.json()
            print(f"✅ Backend healthy: {data}")
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return

        if AGENT_ID and AGENT_API_KEY:
            print(f"\n🔑 Testing agent credentials (ID: {AGENT_ID[:12]}...)")
            ok = self.client.heartbeat(self.ip_address)
            print(f"{'✅ Credentials valid' if ok else '❌ Credentials invalid'}")
        else:
            print("⚠️  AGENT_ID / AGENT_API_KEY not set — run with --register first")

    # ─── Main Loop ───

    def start(self):
        """เริ่มรัน agent (blocking)"""
        if not AGENT_ID or not AGENT_API_KEY:
            log.error("❌ AGENT_ID or AGENT_API_KEY not configured. Run: python3 sentinel_agent.py --register")
            sys.exit(1)

        log.info(f"🚀 SentinelLog Agent v{self.VERSION} starting...")
        log.info(f"   Host    : {self.hostname} ({self.ip_address})")
        log.info(f"   Backend : {BACKEND_URL}")
        log.info(f"   Log file: {NGINX_LOG_PATH}")
        log.info(f"   Firewall: {self.firewall.backend}")

        self._running = True

        # Thread: Heartbeat
        threading.Thread(target=self._heartbeat_loop, daemon=True, name="heartbeat").start()
        # Thread: Command poller
        threading.Thread(target=self._command_loop, daemon=True, name="commands").start()

        # Main thread: Log sender
        self._log_loop()

    def _heartbeat_loop(self):
        """ส่ง heartbeat ทุก HEARTBEAT_INTERVAL วินาที"""
        while self._running:
            ok = self.client.heartbeat(self.ip_address)
            if ok:
                log.debug("💓 Heartbeat OK")
            time.sleep(HEARTBEAT_INTERVAL)

    def _command_loop(self):
        """Poll + execute commands ทุก COMMAND_POLL_INTERVAL วินาที"""
        while self._running:
            commands = self.client.poll_commands()
            for cmd in commands:
                self._handle_command(cmd)
            time.sleep(COMMAND_POLL_INTERVAL)

    def _handle_command(self, cmd: dict):
        """Execute command แล้วรายงานผล"""
        cmd_id = cmd.get("id")
        cmd_type = cmd.get("command_type", "unknown")
        log.info(f"📥 Received command #{cmd_id}: {cmd_type}")

        success, output, error = self.executor.execute(cmd)

        self.client.report_result(
            command_id=cmd_id,
            success=success,
            output=output,
            error=error,
        )

        if success:
            log.info(f"✅ Command #{cmd_id} ({cmd_type}) succeeded")
        else:
            log.error(f"❌ Command #{cmd_id} ({cmd_type}) failed: {error}")

    def _log_loop(self):
        """อ่าน Nginx log แล้วส่งเป็น batch ทุก LOG_BATCH_INTERVAL วินาที"""
        log.info(f"📡 Log sender started (batch every {LOG_BATCH_INTERVAL}s, max {LOG_BATCH_SIZE} per batch)")
        while self._running:
            try:
                batch = self.log_reader.collect_batch()
                if batch:
                    log.info(f"📤 Sending {len(batch)} log(s) to backend...")
                    try:
                        result = self.client.send_logs_batch(batch)
                        processed = result.get("data", {}).get("processed", 0)
                        failed = result.get("data", {}).get("failed", 0)
                        log.info(f"   ↳ processed={processed} failed={failed}")
                    except requests.HTTPError as e:
                        log.error(f"❌ Batch send failed (HTTP {e.response.status_code}): {e.response.text[:200]}")
                    except requests.ConnectionError:
                        log.warning("⚠️  Cannot reach backend — will retry next cycle")
                    except Exception as e:
                        log.error(f"❌ Batch send error: {e}")
                else:
                    log.debug("📭 No new logs")
            except Exception as e:
                log.error(f"Log loop error: {e}")

            time.sleep(LOG_BATCH_INTERVAL)


# ─────────────────────────── Entry Point ───────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SentinelLog Linux Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 sentinel_agent.py --register        # ลงทะเบียนครั้งแรก
  python3 sentinel_agent.py                   # รัน agent
  python3 sentinel_agent.py --test-connection # ทดสอบการเชื่อมต่อ
        """,
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="Register this agent with the backend (run once)",
    )
    parser.add_argument(
        "--test-connection",
        action="store_true",
        help="Test backend connection and credentials",
    )

    args = parser.parse_args()
    agent = SentinelAgent()

    if args.register:
        agent.register()
    elif args.test_connection:
        agent.test_connection()
    else:
        agent.start()


if __name__ == "__main__":
    main()
