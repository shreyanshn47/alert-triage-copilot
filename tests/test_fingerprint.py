from app.fingerprint import fingerprint, normalize_command_line

BASE = dict(
    tenant_id="acme",
    host="WS01",
    user="CORP\\alice",
    process="C:\\Windows\\System32\\powershell.exe",
    command_line="powershell.exe -File patch.ps1",
    event_type="process_create",
)


def fp(**overrides):
    return fingerprint(**{**BASE, **overrides})


def test_identical_alerts_hash_the_same():
    assert fp() == fp()


def test_case_and_whitespace_do_not_matter():
    assert fp(host="ws01", command_line="  POWERSHELL.EXE   -File  patch.ps1 ") == fp()


def test_path_separator_style_does_not_matter():
    assert fp(process="c:/windows/system32/powershell.exe") == fp()


def test_timestamps_guids_pids_and_hex_are_ignored():
    a = fp(command_line="run job 2026-11-01T10:00:00Z id {8f3c1c2e-5d1a-4c1b-9b6e-1a2b3c4d5e6f} pid=123")
    b = fp(command_line="run job 2026-11-02T23:59:59Z id {00000000-1111-2222-3333-444444444444} pid=987")
    assert a == b
    assert fp(command_line="x 0xdeadbeef") == fp(command_line="x 0xcafebabe")


def test_ephemeral_ports_are_ignored_but_low_ports_are_not():
    assert fp(command_line="connect port 51234") == fp(command_line="connect port 60001")
    assert fp(command_line="connect port 22") != fp(command_line="connect port 23")


def test_different_behaviour_gives_different_fingerprints():
    assert fp(command_line="powershell.exe -enc AAAA") != fp()
    assert fp(host="WS02") != fp()
    assert fp(user="CORP\\bob") != fp()
    assert fp(event_type="network_connect") != fp()
    assert fp(process="C:\\Temp\\powershell.exe") != fp()


def test_tenant_is_part_of_the_fingerprint():
    assert fp(tenant_id="acme") != fp(tenant_id="globex")


def test_separator_characters_cannot_forge_a_collision():
    # If fields were joined with a separator, these two could hash the same.
    assert fp(host="a\x1fb", user="") != fp(host="a", user="b")
    assert fp(host="a,b", user="c") != fp(host="a", user="b,c")


def test_missing_fields_do_not_crash():
    assert len(fp(host=None, user=None, process=None, command_line=None)) == 64
    assert normalize_command_line(None) == ""
    assert normalize_command_line("") == ""
