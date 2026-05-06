"""
test_full_session.py — End-to-end verification against the captured
L+G meter read session for serial 51282380.
"""

import hdlc
import cosem
import lg_short


def hexstr(b: bytes) -> str:
    return b.hex(" ").upper()


def test_build(label: str, built: bytes, expected_hex: str) -> bool:
    expected = bytes.fromhex(expected_hex.replace(" ", ""))
    ok = built == expected
    mark = "✓" if ok else "✗"
    print(f"  {mark} {label}")
    if not ok:
        print(f"      built   : {hexstr(built)}")
        print(f"      expected: {hexstr(expected)}")
    return ok


def test_parse(label: str, raw_hex: str, assertion: callable) -> bool:
    try:
        result = assertion(bytes.fromhex(raw_hex.replace(" ", "")))
        ok = result is True or result is None
        mark = "✓" if ok else "✗"
        print(f"  {mark} {label}")
        if not ok:
            print(f"      result: {result}")
        return ok
    except Exception as e:
        print(f"  ✗ {label}  (raised: {e})")
        return False


SERIAL = 51282380

print("=" * 70)
print(f"Full session verification — meter {SERIAL}")
print("=" * 70)

# ---------------------------------------------------------------------------
# Frame 1: SNRM (sent)
# ---------------------------------------------------------------------------
print("\n[1] → SNRM")
test_build(
    "build_snrm_frame matches capture",
    hdlc.build_snrm_frame(SERIAL),
    "7EA023000234692193B018818014050205DC060205DC070400000001080400000001A90D7E",
)

# ---------------------------------------------------------------------------
# Frame 2: UA (received)
# ---------------------------------------------------------------------------
print("\n[2] ← UA")
test_parse(
    "parse_ua_response accepts UA",
    "7EA02121000234697394AC8180120501F806013E070400000001080400000001480E7E",
    hdlc.parse_ua_response,
)

# ---------------------------------------------------------------------------
# Frame 3: AARQ (sent)
# ---------------------------------------------------------------------------
print("\n[3] → AARQ")
aarq = cosem.build_aarq()
test_build(
    "build_aarq PDU matches",
    aarq,
    "602080020780A109060760857405080102BE0F040D01000000065F04001C1320 0000",
)
test_build(
    "full AARQ frame (I-frame, N(S)=0, N(R)=0)",
    hdlc.build_iframe(SERIAL, ns=0, nr=0, info=aarq),
    "7EA031000234692110512CE6E600602080020780A109060760857405080102BE0F040D01000000065F04001C1320000008047E",
)

# ---------------------------------------------------------------------------
# Frame 4: AARE (received)
# ---------------------------------------------------------------------------
print("\n[4] ← AARE")
raw = bytes.fromhex("7EA0392100023469302EB7E6E7006128A109060760857405080102A203020100A305A103020100BE0F040D0800065F04001802200960FA0064C27E")
parsed = hdlc.parse_iframe(raw)
assert parsed is not None and parsed["has_llc"]
aare = cosem.parse_aare(parsed["info"])
print(f"  ✓ AARE parsed: result={aare['result']} (0=accepted), source={aare['result_source']}, diagnostic={aare['result_diagnostic']}")
print(f"    server_max_pdu={aare['server_max_pdu']}, conformance={hexstr(aare['negotiated_conformance']) if aare['negotiated_conformance'] else None}")

# ---------------------------------------------------------------------------
# Frame 5: Multi-read FD08 + FF08 (sent)
# ---------------------------------------------------------------------------
print("\n[5] → Multi-read FD08 + FF08")
pdu = lg_short.build_multi_read_request([
    lg_short.EXT_ADDRESSES["manufacturer_and_serial"],
    lg_short.EXT_ADDRESSES["meter_type_code"],
])
test_build(
    "multi-read PDU",
    pdu,
    "050202FD0802FF08",
)
test_build(
    "full multi-read frame (N(S)=1, N(R)=1)",
    hdlc.build_iframe(SERIAL, ns=1, nr=1, info=pdu),
    "7EA0170002346921320F15E6E600050202FD0802FF0854587E",
)

# ---------------------------------------------------------------------------
# Frame 6: Multi-read response (received)
# ---------------------------------------------------------------------------
print("\n[6] ← Multi-read response")
raw = bytes.fromhex("7EA02A2100023469529DEAE6E7000C020009104C475A35313238323338300000000000000A03423332F5367E")
parsed = hdlc.parse_iframe(raw)
items = lg_short.parse_multi_read_response(parsed["info"])
print(f"  ✓ Parsed {len(items)} items:")
for i, item in enumerate(items, 1):
    print(f"    item {i}: type=0x{item.data_type:02X}, value={item.as_visible_string()!r}")

# ---------------------------------------------------------------------------
# Frame 7: Read 0x3848 (sent)
# ---------------------------------------------------------------------------
print("\n[7] → Read device_identification (0x3848)")
test_build(
    "read request PDU",
    lg_short.build_read_request_by_name("device_identification"),
    "0501023848",
)
test_build(
    "full read frame (N(S)=2, N(R)=2)",
    hdlc.build_iframe(SERIAL, ns=2, nr=2, info=lg_short.build_read_request(0x3848)),
    "7EA01400023469215451BBE6E600050102384806257E",
)

# ---------------------------------------------------------------------------
# Frame 8: Read response (received)
# ---------------------------------------------------------------------------
print("\n[8] ← Response to 0x3848")
raw = bytes.fromhex("7EA0392100023469740EB3E6E7000C01000A25422E4D344343505453434D444F2E303437392E41543053547647736172485350706E61676C69607E")
parsed = hdlc.parse_iframe(raw)
resp = lg_short.parse_read_response(parsed["info"])
print(f"  ✓ success={resp.success}, data_type=0x{resp.data_type:02X}, value={resp.as_visible_string()!r}")

# ---------------------------------------------------------------------------
# Frame 9: Read 0xC1C8 (sent)
# ---------------------------------------------------------------------------
print("\n[9] → Read device_id_1 (0xC1C8)")
test_build(
    "full read frame (N(S)=3, N(R)=3)",
    hdlc.build_iframe(SERIAL, ns=3, nr=3, info=lg_short.build_read_request(0xC1C8)),
    "7EA01400023469217641B9E6E600050102C1C81E0A7E",
)

# ---------------------------------------------------------------------------
# Frame 10: Read response (received)
# ---------------------------------------------------------------------------
print("\n[10] ← Response to 0xC1C8")
raw = bytes.fromhex("7EA027210002346996FA44E6E7000C0100091302CB0000FF0000043000045000048001048002F19F7E")
parsed = hdlc.parse_iframe(raw)
resp = lg_short.parse_read_response(parsed["info"])
print(f"  ✓ success={resp.success}, data_type=0x{resp.data_type:02X}, {len(resp.value)} bytes: {hexstr(resp.value)}")

# ---------------------------------------------------------------------------
# Frame 11: Read 0x5A88 (sent)
# ---------------------------------------------------------------------------
print("\n[11] → Read serial_number (0x5A88)")
test_build(
    "full read frame (N(S)=4, N(R)=4)",
    hdlc.build_iframe(SERIAL, ns=4, nr=4, info=lg_short.build_read_request(0x5A88)),
    "7EA01400023469219831B7E6E6000501025A88EFB57E",
)

# ---------------------------------------------------------------------------
# Frame 12: Read response (received)
# ---------------------------------------------------------------------------
print("\n[12] ← Response to 0x5A88")
raw = bytes.fromhex("7EA01C2100023469B84E2CE6E7000C01000A0835313238323338304B217E")
parsed = hdlc.parse_iframe(raw)
resp = lg_short.parse_read_response(parsed["info"])
print(f"  ✓ success={resp.success}, data_type=0x{resp.data_type:02X}, value={resp.as_visible_string()!r}")

# ---------------------------------------------------------------------------
# Frame 13: DISC (sent)
# ---------------------------------------------------------------------------
print("\n[13] → DISC")
test_build(
    "build_disc_frame matches",
    hdlc.build_disc_frame(SERIAL),
    "7EA00A00023469215306FC7E",
)

# ---------------------------------------------------------------------------
# Frame 14: UA (received, session closed)
# ---------------------------------------------------------------------------
print("\n[14] ← UA (session closed)")
test_parse(
    "parse_ua_response accepts closing UA",
    "7EA02121000234697394AC8180120501F806013E070400000001080400000001480E7E",
    hdlc.parse_ua_response,
)

print("\n" + "=" * 70)
print("Done.")
