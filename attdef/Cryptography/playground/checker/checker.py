#!/usr/bin/env python3
from __future__ import annotations

import hmac
import ipaddress
import ast
import json
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

OK, MUMBLE, OFFLINE, INTERNAL_ERROR = 0, 1, 2, 3
NAME = {OK: "Ok", MUMBLE: "Mumble", OFFLINE: "Offline", INTERNAL_ERROR: "InternalError"}
MAX_BODY = 1024 * 1024
MAX_FLAGS = 1000


class CheckError(Exception):
    status = INTERNAL_ERROR


class Mumble(CheckError):
    status = MUMBLE


class Offline(CheckError):
    status = OFFLINE


@dataclass(frozen=True)
class RetainedFlag:
    id: int
    value: str
    planted_at_tick: int
    placement: str


@dataclass
class Target:
    ip: str
    port: int
    round: int
    tick: int
    tick_number: int
    round_start_tick: int
    team_id: str
    challenge_id: int
    flags: tuple[RetainedFlag, ...]
    deadline: float = field(default_factory=lambda: time.monotonic() + 24)
    session: requests.Session = field(default_factory=requests.Session, repr=False)

    def __post_init__(self):
        self.session.trust_env = False

    @property
    def url(self):
        host = "[" + self.ip + "]" if ":" in self.ip else self.ip
        return f"http://{host}:{self.port}"

    def request(self, method, path="/", **kwargs):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Offline("target response deadline exceeded")
        kwargs.setdefault("timeout", min(3, remaining))
        kwargs["allow_redirects"] = False
        kwargs["stream"] = True
        try:
            response = self.session.request(method, self.url + path, **kwargs)
            chunks, size = [], 0
            for chunk in response.iter_content(1):
                if time.monotonic() >= self.deadline:
                    response.close()
                    raise Offline("target response deadline exceeded")
                size += len(chunk)
                if size > MAX_BODY:
                    response.close()
                    raise Mumble("service response exceeded the maximum size")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
            response.close()
            return response
        except requests.RequestException:
            raise Offline("target transport failed") from None

    def get(self, path="/", **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path="/", **kwargs):
        return self.request("POST", path, **kwargs)


def integer(value, name, low=1, high=2147483647):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid " + name)
    return value


def worker_target(payload):
    if not isinstance(payload, dict) or type(payload.get("protocolVersion")) is not int or payload["protocolVersion"] != 2:
        raise ValueError("only checker protocol V2 is supported")
    host = payload.get("targetIp")
    if not isinstance(host, str):
        raise ValueError("invalid targetIp")
    host = str(ipaddress.ip_address(host))
    tick_number = integer(payload.get("tickNumber"), "tickNumber")
    round_start_tick = integer(payload.get("roundStartTick"), "roundStartTick", high=tick_number)
    tick = integer(payload.get("tick"), "tick")
    if tick != tick_number - round_start_tick + 1:
        raise ValueError("tick does not match its flag round")
    team_id = payload.get("teamId")
    if not isinstance(team_id, str) or not team_id.isascii() or not team_id.isdigit() or len(team_id) > 20 or int(team_id) < 1:
        raise ValueError("invalid teamId")
    raw_flags = payload.get("flags")
    if not isinstance(raw_flags, list) or not 1 <= len(raw_flags) <= MAX_FLAGS:
        raise ValueError("invalid retained flags")
    flags, seen_ids, seen_values = [], set(), set()
    for item in raw_flags:
        if not isinstance(item, dict):
            raise ValueError("invalid retained flag")
        flag_id = integer(item.get("id"), "flag id")
        value = item.get("flag")
        issued = integer(item.get("plantedAtTick"), "plantedAtTick", high=round_start_tick)
        placement = item.get("placement")
        if not isinstance(value, str) or not 1 <= len(value) <= 4096 or flag_id in seen_ids or value in seen_values:
            raise ValueError("invalid or duplicate retained flag")
        if placement not in ("new", "unknown", "confirmed", "failed"):
            raise ValueError("platform-v1 placement state required")
        if placement == "new" and (issued != round_start_tick or tick_number != round_start_tick):
            raise ValueError("new flags require the first tick of their round")
        flags.append(RetainedFlag(flag_id, value, issued, placement))
        seen_ids.add(flag_id)
        seen_values.add(value)
    if not any(flag.planted_at_tick == round_start_tick for flag in flags):
        raise ValueError("no current-round flag provided")
    return Target(ip=host, port=integer(payload.get("targetPort"), "targetPort", high=65535),
                  round=integer(payload.get("round"), "round"), tick=tick,
                  tick_number=tick_number, round_start_tick=round_start_tick,
                  team_id=team_id, challenge_id=integer(payload.get("challengeId"), "challengeId"),
                  flags=tuple(flags))


TCP_BUFFER_LIMIT = 64 * 1024
TCP_TIMEOUT = 4


def _recv_until(connection, marker):
    data = bytearray()
    while marker not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise Mumble("target closed the connection before its response")
        data.extend(chunk)
        if len(data) > TCP_BUFFER_LIMIT:
            raise Mumble("target response exceeded the maximum size")
    return bytes(data)


def _send_request(connection, request, marker):
    connection.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
    return _recv_until(connection, marker).decode("utf-8", errors="replace")


def _flip_hex(value):
    replacement = "0" if value[0] != "0" else "1"
    return replacement + value[1:]


def _expect_message(connection, request, message):
    response = _send_request(connection, request, message.encode())
    if message not in response:
        raise Mumble("unexpected response message")


def _expect_raw_message(connection, raw_request, message):
    connection.sendall(raw_request + b"\n")
    response = _recv_until(connection, message.encode()).decode("utf-8", errors="replace")
    if message not in response:
        raise Mumble("unexpected response message")


def check_service(target):
    try:
        connection = socket.create_connection((target.ip, target.port), timeout=TCP_TIMEOUT)
    except OSError:
        raise Offline("target TCP service is unreachable") from None

    with connection:
        connection.settimeout(TCP_TIMEOUT)
        _expect_message(connection, {}, "Invalid request")
        _expect_message(connection, {"command": "unknown"}, "Invalid command")
        _expect_message(connection, {"command": "get"}, "need arguments")
        _expect_message(connection, {"command": "claim"}, "need arguments")
        _expect_message(connection, {"command": "claim", "ticket": "x"}, "need arguments")
        _expect_message(connection, {"command": "claim", "signature": "x"}, "need arguments")
        _expect_raw_message(connection, b"not-json", "Something went wrong, please try again.")

        response = _send_request(connection, {"command": "get", "user": "sla-checker"},
                                  b"save your ticket: ")
        try:
            ticket = ast.literal_eval(response.rsplit("save your ticket: ", 1)[1].strip())
            if set(ticket) != {"ticket", "signature"}:
                raise ValueError
            encrypted_ticket = ticket["ticket"]
            signature = ticket["signature"]
            if not isinstance(encrypted_ticket, str) or not isinstance(signature, str):
                raise ValueError
            encrypted_bytes = bytes.fromhex(encrypted_ticket)
            signature_bytes = bytes.fromhex(signature)
            if not encrypted_bytes or len(encrypted_bytes) % 16 != 0:
                raise ValueError
            if len(signature_bytes) != 256:
                raise ValueError
        except (KeyError, TypeError, ValueError, SyntaxError):
            raise Mumble("get returned an invalid ticket") from None

        response = _send_request(connection,
                                  {"command": "claim", "ticket": encrypted_ticket,
                                   "signature": signature},
                                  b"not for you, sorry")
        if "ticket confirmation:" not in response or "Invalid signature" in response:
            raise Mumble("valid ticket was not accepted")
        try:
            confirmation = response.rsplit("ticket confirmation: ", 1)[1].split(
                "\nnot for you, sorry", 1
            )[0].strip()
            readable_ticket = ast.literal_eval(confirmation)
            ticket_data = json.loads(readable_ticket)
        except (IndexError, TypeError, ValueError, SyntaxError, json.JSONDecodeError):
            raise Mumble("valid ticket was not decryptable JSON") from None
        if (not isinstance(ticket_data, dict)
            or set(ticket_data) != {"timestamp", "user", "role", "access"}
                or not isinstance(ticket_data["timestamp"], str)
                or ticket_data["user"] != "sla-checker"
                or ticket_data["role"] != "guest"
                or ticket_data["access"] is not False):
            raise Mumble("decrypted ticket structure changed")

        tampered_ticket = _flip_hex(encrypted_ticket)
        response = _send_request(connection,
                                  {"command": "claim", "ticket": tampered_ticket,
                                   "signature": signature},
                                  b"Invalid signature")
        if "Invalid signature" not in response:
            raise Mumble("tampered ticket was accepted")

        tampered_signature = _flip_hex(signature)
        response = _send_request(connection,
                                  {"command": "claim", "ticket": encrypted_ticket,
                                   "signature": tampered_signature},
                                  b"Invalid signature")
        if "Invalid signature" not in response:
            raise Mumble("tampered signature was accepted")


def run_check(target):
    results = [{"id": flag.id, "retrievable": False,
                "placement": "unknown" if flag.placement == "new" else flag.placement}
               for flag in target.flags]
    status = OK
    try:
        check_service(target)
    except CheckError as exc:
        status = exc.status
    except Exception:
        status = INTERNAL_ERROR

    if status == OK:
        for result in results:
            result["retrievable"] = True
            result["placement"] = "confirmed"
    else:
        for flag, result in zip(target.flags, results):
            if flag.placement == "new":
                result["placement"] = "failed"

    response = {"status": NAME[status], "code": status, "flags": results}
    if status != OK:
        response["message"] = {MUMBLE: "ordinary service functionality failed",
                               OFFLINE: "target service is unreachable",
                               INTERNAL_ERROR: "checker execution failed"}[status]
    target.session.close()
    return response


class WorkerServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, token):
        if not token:
            raise ValueError("GZCTF_CHECKER_TOKEN must be configured")
        self.token = token
        self.check_lock = threading.Lock()
        super().__init__(address, WorkerHandler)


class WorkerHandler(BaseHTTPRequestHandler):
    server_version = "GZCTF-Checker-Worker/2"

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def send_json(self, status, body):
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_json(200, {"status": "ready", "protocolVersion": 2,
                                 "flagPlacement": "platform-v1", "groupedRounds": True})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/check":
            self.send_json(404, {"error": "not found"})
            return
        supplied = self.headers.get("X-GZCTF-Checker-Token", "")
        if not hmac.compare_digest(supplied.encode(), self.server.token.encode()):
            self.send_json(401, {"status": "InternalError", "code": INTERNAL_ERROR})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY or self.headers.get("Transfer-Encoding"):
                raise ValueError("invalid request length")
            if self.headers.get_content_type() != "application/json":
                raise ValueError("application/json required")
            target = worker_target(json.loads(self.rfile.read(length)))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.send_json(400, {"status": "InternalError", "code": INTERNAL_ERROR, "error": "invalid V2 request"})
            return
        if not self.server.check_lock.acquire(blocking=False):
            target.session.close()
            self.send_json(503, {"status": "InternalError", "code": INTERNAL_ERROR, "error": "worker is busy"})
            return
        try:
            result = run_check(target)
        finally:
            self.server.check_lock.release()
        self.send_json(200, result)

    def log_message(self, *_args):
        pass


def main():
    host = os.environ.get("GZCTF_CHECKER_BIND", "0.0.0.0")
    port = int(os.environ.get("GZCTF_CHECKER_PORT", "8081"))
    server = WorkerServer((host, port), os.environ.get("GZCTF_CHECKER_TOKEN", ""))
    print(f"V2 checker worker listening on {host}:{port}", file=sys.stderr, flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
