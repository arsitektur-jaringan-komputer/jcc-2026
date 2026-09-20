#!/usr/bin/env python3
"""
A&D checker harness. You normally DON'T edit this file — add your test
cases in checks.py (just write a function and decorate it with @check).

The platform runs this image once per (team, tick) with these env vars:
  GZCTF_TARGET_IP    the team's service IP
  GZCTF_TARGET_PORT  its exposed port
  GZCTF_FLAG         the flag planted into the service THIS tick
  GZCTF_ROUND        round number (int)
  GZCTF_TEAM_ID      id of the team being checked

Every @check function in checks.py runs in order. To report a verdict,
either return normally (the check passed) or raise:
  Mumble(msg)   service reachable but wrong (bad flag, broken endpoint)
  Offline(msg)  can't reach the service — Target.get/post raise this for you
Anything else that bubbles out is treated as InternalError (your bug,
not the team's; the platform doesn't penalize a team for a broken checker).

The process exits with the WORST verdict seen across all checks, which the
platform maps to a status:
  0 Ok | 1 Mumble | 2 Offline | 3 InternalError
"""
from __future__ import annotations

import os
import json
import re
import socket
import sys
import traceback
from dataclasses import dataclass

import requests

# enochecker3 exit-code contract. Ordered by severity so max() aggregates
# correctly: a single Offline beats any number of Oks, etc.
OK, MUMBLE, OFFLINE, INTERNAL_ERROR = 0, 1, 2, 3
_NAME = {OK: "Ok", MUMBLE: "Mumble", OFFLINE: "Offline", INTERNAL_ERROR: "InternalError"}


class CheckError(Exception):
    """Base for verdict-bearing exceptions. Bare raises = InternalError."""

    status = INTERNAL_ERROR


class Mumble(CheckError):
    """Service is up but behaving wrong (bad flag, broken response)."""

    status = MUMBLE


class Offline(CheckError):
    """Couldn't reach the service at all (refused / timeout / DNS)."""

    status = OFFLINE


_CHECKS: list = []


def check(fn):
    """Register a test case. The function receives a single Target arg."""
    _CHECKS.append(fn)
    return fn


@dataclass
class Target:
    """The team's service + this tick's context, handed to every check."""

    ip: str
    port: int
    flag: str
    round: int
    team_id: str

    @property
    def url(self) -> str:
        return f"http://{self.ip}:{self.port}"

    def get(self, path: str = "/", **kw) -> "requests.Response":
        return self._request("GET", path, **kw)

    def post(self, path: str = "/", **kw) -> "requests.Response":
        return self._request("POST", path, **kw)

    def request(self, method: str, path: str = "/", **kw) -> "requests.Response":
        return self._request(method, path, **kw)

    def get_and_claim(self, user: str, mutate_ticket=None) -> str:
        """Issue and claim a ticket without changing the service process."""
        try:
            with socket.create_connection((self.ip, self.port), timeout=5) as conn:
                conn.settimeout(5)
                output = []
                conn.sendall((json.dumps({"command": "get", "user": user}) + "\n").encode())
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return "".join(output)
                    output.append(chunk.decode(errors="replace"))
                    text = "".join(output)
                    match = re.search(r"save your ticket:\s*([0-9a-fA-F]+)", text)
                    if match:
                        break

                ticket = match.group(1)
                if len(ticket) == 0 or len(ticket) % 32 != 0:
                    return text
                if mutate_ticket is not None:
                    ticket = mutate_ticket(ticket)
                conn.sendall((json.dumps({"command": "claim", "ticket": ticket}) + "\n").encode())
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return "".join(output)
                    output.append(chunk.decode(errors="replace"))
                    text = "".join(output)
                    if any(marker in text for marker in (
                        "not for you, sorry",
                        "save your flag:",
                        "flag is not ready yet",
                        "Something went wrong",
                    )):
                        return text
        except (OSError, socket.timeout) as e:
            raise Offline(f"TCP request failed: {e}") from e

    def send_requests(self, payloads: list[str]) -> str:
        """Send raw line requests and return the service output."""
        try:
            with socket.create_connection((self.ip, self.port), timeout=5) as conn:
                conn.settimeout(1)
                for payload in payloads:
                    conn.sendall((payload + "\n").encode())
                chunks = []
                while True:
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk.decode(errors="replace"))
                return "".join(chunks)
        except OSError as e:
            raise Offline(f"TCP request failed: {e}") from e

    def _request(self, method: str, path: str, **kw) -> "requests.Response":
        kw.setdefault("timeout", 5)
        try:
            return requests.request(method, self.url + path, **kw)
        except requests.exceptions.RequestException as e:
            # No response at all → the service is down for us. Checks that
            # want to assert on content will simply never reach that code.
            raise Offline(f"{method} {path}: {e}") from e


def _target_from_env() -> Target:
    try:
        return Target(
            ip=os.environ["GZCTF_TARGET_IP"],
            port=int(os.environ["GZCTF_TARGET_PORT"]),
            flag=os.environ.get("GZCTF_FLAG", ""),
            round=int(os.environ.get("GZCTF_ROUND", "0")),
            team_id=os.environ.get("GZCTF_TEAM_ID", ""),
        )
    except (KeyError, ValueError) as e:
        print(f"checker misconfigured (bad/missing env): {e}", file=sys.stderr)
        sys.exit(INTERNAL_ERROR)


def main() -> None:
    # Note: the @check functions are registered by importing checks.py,
    # which run.py does before calling us. We deliberately don't `import
    # checks` here — running this file directly as __main__ would create a
    # second copy of this module under the name "checker", and the
    # decorators in checks.py would register into THAT copy's list instead
    # of this one. run.py sidesteps that by only ever importing by name.
    if not _CHECKS:
        print("no checks registered — run via run.py (python3 run.py), "
              "and add @check functions in checks.py", file=sys.stderr)
        sys.exit(INTERNAL_ERROR)

    target = _target_from_env()
    worst = OK
    for fn in _CHECKS:
        name = getattr(fn, "__name__", "check")
        try:
            fn(target)
        except CheckError as e:
            worst = max(worst, e.status)
            print(f"[{name}] {_NAME[e.status]}: {e}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001 — any stray error is our bug
            worst = max(worst, INTERNAL_ERROR)
            print(f"[{name}] InternalError: {e}", file=sys.stderr)
            traceback.print_exc()
        else:
            print(f"[{name}] Ok", file=sys.stderr)

    print(f"verdict: {_NAME[worst]}", file=sys.stderr)
    sys.exit(worst)


if __name__ == "__main__":
    # Running this file directly skips checks.py registration (see the note
    # in main()). Point the user at the right entrypoint instead of silently
    # reporting "no checks".
    print("run the checker via run.py:  python3 run.py", file=sys.stderr)
    sys.exit(INTERNAL_ERROR)
