import ast
import json
import re

from checker import Mumble, check

@check
def check_ticket_flow(t):
    user = "deadbeef."
    response = t.get_and_claim(user)
    ticket_match = re.search(r"save your ticket:\s*([0-9a-fA-F]+)", response)
    if ticket_match is None:
        raise Mumble("ticket was not issued")
    if len(ticket_match.group(1)) == 0 or len(ticket_match.group(1)) % 32 != 0:
        raise Mumble("service issued an invalid ticket")

    confirmation = re.search(r"ticket confirmation:\s*(b'.*')", response)
    if confirmation is None:
        raise Mumble("ticket confirmation missing")

    try:
        ticket_data = json.loads(ast.literal_eval(confirmation.group(1)).decode())
    except (ValueError, SyntaxError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise Mumble("ticket confirmation is malformed") from e

    if list(ticket_data) != ["timestamp", "user", "role", "access"]:
        raise Mumble("ticket confirmation was tampered")
    if (
        not re.fullmatch(r"[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \d{4}", ticket_data["timestamp"])
        or ticket_data["user"] != user
        or ticket_data["role"] != "guest"
        or ticket_data["access"] is not False
    ):
        raise Mumble("ticket confirmation was tampered")

    if "not for you, sorry" not in response:
        raise Mumble("guest ticket was not rejected")
    if t.flag and t.flag in response:
        raise Mumble("flag leaked through a guest ticket")


@check
def check_response_consistency(t):
    cases = (
        ('{"command":"get","user":"deadbeef."}', "save your ticket:"),
        ('{"command":"claim","ticket":"00"}', "Something went wrong, please try again."),
        ('{"command":"get"}', "need arguments"),
        ('{"command":"claim"}', "need arguments"),
        ('{"command":"debug","user":"deadbeef."}', "Invalid command"),
        ('{}', "Invalid request"),
        ('not-json', "Something went wrong, please try again."),
    )

    for request, expected in cases:
        response = t.send_requests([request])
        if expected not in response:
            raise Mumble(f"unexpected response for {request}: {response!r}")

    response = t.get_and_claim("deadbeef.")
    for expected in ("ticket confirmation:", "not for you, sorry"):
        if expected not in response:
            raise Mumble(f"claim response missing {expected!r}")


@check
def check_availability(t):
    response = t.send_requests(["{}"])
    if "Invalid request" not in response:
        raise Mumble("service did not answer availability probe")


@check
def check_ticket_integrity(t):
    for user in ("deadbeef.", "checker1.", "123456789"):
        response = t.get_and_claim(user)
        if f'"user": "{user}"' not in response:
            raise Mumble(f"ticket user was not preserved for {user!r}")
        if '"role": "guest"' not in response or '"access": false' not in response:
            raise Mumble(f"ticket claims changed for {user!r}")
        if "not for you, sorry" not in response:
            raise Mumble(f"guest ticket was accepted for {user!r}")


@check
def check_ticket_tampering(t):
    def flip_first_nibble(ticket):
        replacement = "0" if ticket[0].lower() != "0" else "1"
        return replacement + ticket[1:]

    response = t.get_and_claim("deadbeef.", mutate_ticket=flip_first_nibble)
    if t.flag and t.flag in response:
        raise Mumble("tampered ticket leaked the flag")
    if "save your flag:" in response:
        raise Mumble("tampered ticket reached flag response")


@check
def check_input_boundaries(t):
    cases = (
        ('{"command":"get","user":""}', "Something went wrong, please try again."),
        ('{"command":"get","user":"short"}', "Something went wrong, please try again."),
        ('{"command":"get","user":123}', "Something went wrong, please try again."),
        ('{"command":"claim","ticket":"zz"}', "Something went wrong, please try again."),
    )
    for request, expected in cases:
        response = t.send_requests([request])
        if expected not in response:
            raise Mumble(f"boundary response mismatch for {request}: {response!r}")


@check
def check_service_recovery(t):
    response = t.send_requests([
        "not-json",
        '{"command":"claim","ticket":"00"}',
        '{"command":"get","user":"deadbeef."}',
    ])
    if "Something went wrong, please try again." not in response:
        raise Mumble("malformed request response changed")
    if "save your ticket:" not in response:
        raise Mumble("service did not recover after malformed requests")


@check
def check_guest_flag_isolation(t):
    response = t.get_and_claim("deadbeef.")
    if t.flag and t.flag in response:
        raise Mumble("guest flow leaked the current flag")
    if "save your flag:" in response:
        raise Mumble("guest flow reached flag output")
