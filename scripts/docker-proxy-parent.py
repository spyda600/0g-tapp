#!/usr/bin/env python3
"""
Docker proxy for Nitro Enclave parent EC2 instance.

Listens on a vsock port and executes Docker commands sent by the enclave.
The enclave cannot run Docker directly; it sends JSON requests over vsock,
and this script executes them on the parent where Docker is available.

Wire format (length-prefixed JSON):
  [4-byte big-endian length][JSON payload]

Usage:
  sudo python3 docker-proxy-parent.py          # default port 50052
  sudo python3 docker-proxy-parent.py --port 50052 --allowed-base /var/lib/tapp/apps
"""

import argparse
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import threading

# AF_VSOCK constants
AF_VSOCK = 40
VMADDR_CID_ANY = 0xFFFFFFFF

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("docker-proxy")

ALLOWED_BASE = "/var/lib/tapp/apps"


def validate_working_dir(working_dir: str) -> bool:
    """Ensure the working directory is under the allowed base path."""
    if not working_dir:
        return False
    real = os.path.realpath(working_dir)
    return real.startswith(os.path.realpath(ALLOWED_BASE))


def validate_name(name: str, field: str) -> str:
    """Validate that a name (service, container, image) is safe for CLI use.
    Prevents argument injection via Docker CLI flags."""
    import re
    if not name:
        raise ValueError(f"{field} cannot be empty")
    if len(name) > 256:
        raise ValueError(f"{field} too long (max 256 chars)")
    # Allow alphanumeric, hyphens, underscores, dots, colons, slashes (for image tags)
    if not re.match(r'^[a-zA-Z0-9._:/@-]+$', name):
        raise ValueError(f"{field} contains invalid characters: {name!r}")
    # Must not start with a hyphen (prevents --flag injection)
    if name.startswith('-'):
        raise ValueError(f"{field} must not start with '-': {name!r}")
    return name


def recv_exact(conn: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading")
        buf += chunk
    return buf


def send_response(conn: socket.socket, resp: dict):
    """Send a length-prefixed JSON response."""
    payload = json.dumps(resp).encode("utf-8")
    conn.sendall(struct.pack("!I", len(payload)))
    conn.sendall(payload)


def run_command(args: list, cwd: str = None, timeout: int = 300) -> dict:
    """Execute a command and return the result dict."""
    log.info("Executing: %s (cwd=%s)", " ".join(args), cwd)
    try:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s",
            "exit_code": -1,
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "exit_code": -1,
        }


def handle_request(req: dict) -> dict:
    """Dispatch a single request to the appropriate handler."""
    command = req.get("command", "")
    working_dir = req.get("working_dir", "")
    app_id = req.get("app_id", "")

    # Validate working_dir for commands that use it
    if working_dir and not validate_working_dir(working_dir):
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Disallowed working directory: {working_dir}",
            "exit_code": -1,
        }

    if command == "compose_up":
        compose_content = req.get("compose_content", "")
        if not compose_content or not working_dir:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_up requires compose_content and working_dir",
                "exit_code": -1,
            }
        # Ensure directory exists
        os.makedirs(working_dir, exist_ok=True)
        compose_path = os.path.join(working_dir, "docker-compose.yml")
        with open(compose_path, "w") as f:
            f.write(compose_content)
        return run_command(
            ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"],
            cwd=working_dir,
            timeout=600,
        )

    elif command == "compose_down":
        if not working_dir:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_down requires working_dir",
                "exit_code": -1,
            }
        return run_command(
            ["docker", "compose", "down"],
            cwd=working_dir,
        )

    elif command == "compose_logs":
        if not working_dir:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_logs requires working_dir",
                "exit_code": -1,
            }
        args = ["docker", "compose", "logs"]
        tail = req.get("tail", 0)
        if tail and tail > 0:
            args.extend(["--tail", str(tail)])
        service_name = req.get("service_name")
        if service_name:
            validate_name(service_name, "service_name")
            args.append(service_name)
        return run_command(args, cwd=working_dir)

    elif command == "compose_ps":
        if not working_dir:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_ps requires working_dir",
                "exit_code": -1,
            }
        return run_command(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=working_dir,
        )

    elif command == "compose_images":
        if not working_dir:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_images requires working_dir",
                "exit_code": -1,
            }
        return run_command(
            ["docker", "compose", "images", "--format", "json"],
            cwd=working_dir,
        )

    elif command == "compose_stop_service":
        service_name = req.get("service_name", "")
        if not working_dir or not service_name:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_stop_service requires working_dir and service_name",
                "exit_code": -1,
            }
        return run_command(
            ["docker", "compose", "stop", "--", validate_name(service_name, "service_name")],
            cwd=working_dir,
        )

    elif command == "compose_start_service":
        service_name = req.get("service_name", "")
        pull_image = req.get("pull_image", False)
        if not working_dir or not service_name:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_start_service requires working_dir and service_name",
                "exit_code": -1,
            }
        args = ["docker", "compose", "up", "-d"]
        if pull_image:
            args.extend(["--pull", "always"])
        args.append(service_name)
        return run_command(args, cwd=working_dir, timeout=600)

    elif command == "compose_is_service_running":
        service_name = req.get("service_name", "")
        if not working_dir:
            return {
                "success": False,
                "stdout": "",
                "stderr": "compose_is_service_running requires working_dir",
                "exit_code": -1,
            }
        return run_command(
            [
                "docker", "compose", "ps",
                "--services", "--filter", "status=running", "--format", "json",
            ],
            cwd=working_dir,
        )

    elif command == "inspect_digest":
        image_id = req.get("image_id", "")
        if not image_id:
            return {
                "success": False,
                "stdout": "",
                "stderr": "inspect_digest requires image_id",
                "exit_code": -1,
            }
        return run_command(
            ["docker", "inspect", "--format={{index .RepoDigests 0}}", "--", validate_name(image_id, "image_id")],
        )

    elif command == "inspect_started_at":
        container_name = req.get("container_name", "")
        if not container_name:
            return {
                "success": False,
                "stdout": "",
                "stderr": "inspect_started_at requires container_name",
                "exit_code": -1,
            }
        return run_command(
            ["docker", "inspect", "--format={{.State.StartedAt}}", "--", validate_name(container_name, "container_name")],
        )

    elif command == "system_prune":
        prune_all = req.get("prune_all", False)
        args = ["docker", "system", "prune", "-f"]
        if prune_all:
            args.append("--all")
        return run_command(args)

    else:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Unknown command: {command}",
            "exit_code": -1,
        }


def handle_connection(conn: socket.socket, addr):
    """Handle a single vsock connection."""
    peer = f"CID={addr[0]} port={addr[1]}" if len(addr) >= 2 else str(addr)
    log.info("New connection from %s", peer)
    try:
        # Read length prefix
        raw_len = recv_exact(conn, 4)
        msg_len = struct.unpack("!I", raw_len)[0]

        # Safety bound: reject messages larger than 16 MiB
        if msg_len > 16 * 1024 * 1024:
            log.warning("Request too large (%d bytes) from %s", msg_len, peer)
            send_response(conn, {
                "success": False,
                "stdout": "",
                "stderr": "Request too large",
                "exit_code": -1,
            })
            return

        raw_body = recv_exact(conn, msg_len)
        req = json.loads(raw_body)
        log.info("Request from %s: command=%s app_id=%s",
                 peer, req.get("command"), req.get("app_id"))

        resp = handle_request(req)
        send_response(conn, resp)

    except Exception as e:
        log.exception("Error handling connection from %s: %s", peer, e)
        try:
            send_response(conn, {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
            })
        except Exception:
            pass
    finally:
        conn.close()
        log.info("Connection closed from %s", peer)


def main():
    parser = argparse.ArgumentParser(description="Docker proxy for Nitro Enclave parent")
    parser.add_argument("--port", type=int, default=50052,
                        help="Vsock port to listen on (default: 50052)")
    parser.add_argument("--allowed-base", type=str, default="/var/lib/tapp/apps",
                        help="Allowed base path for working directories")
    args = parser.parse_args()

    global ALLOWED_BASE
    ALLOWED_BASE = args.allowed_base

    sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((VMADDR_CID_ANY, args.port))
    sock.listen(5)

    log.info("Docker proxy listening on vsock port %d (allowed base: %s)",
             args.port, ALLOWED_BASE)

    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
