from checker import check, Mumble

@check
def check_notes_service(t):
    # t.flag is the current tick's flag, read from /flag inside your box
    resp = t.post("/note", json={"content": t.flag})
    if resp.status_code != 200:
        raise Mumble("failed to store note")

    note_id = resp.json().get("id")
    if note_id is None:
        raise Mumble("store response missing note id")

    resp = t.get(f"/note/{note_id}")
    if t.flag not in resp.text:
        raise Mumble("planted flag not retrievable")