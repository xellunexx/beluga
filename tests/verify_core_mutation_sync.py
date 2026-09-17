from __future__ import annotations

import hashlib
import importlib
import traceback


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    # Import the actual project modules. This is intentionally not a stubbed
    # environment: the point is to validate core-level synchronization.
    tlv = importlib.import_module("tlv")
    mutations = importlib.import_module("mutations")
    mutation_scenarios = importlib.import_module("mutation_scenarios")

    print("=== CORE MUTATION SYNC ===")
    print("tlv:", getattr(tlv, "__file__", "?"))
    print("mutations:", getattr(mutations, "__file__", "?"))
    print("mutation_scenarios:", getattr(mutation_scenarios, "__file__", "?"))

    # 1. TLV self-test.
    self_test = tlv.self_test()
    print("tlv.self_test:", self_test)
    assert self_test["status"] == "PASS"

    # 2. Registry validation, when supplied by the canonical scenario module.
    if hasattr(mutation_scenarios, "validate_registry"):
        registry = mutation_scenarios.validate_registry()
        print("scenario registry:", registry.get("status"))
        assert registry.get("status") == "PASS", registry

    # 3. Positive READ RECORD mutation.
    # Valid outer 70 length (0x3E), valid 16-byte 8E value, non-zero IACs.
    positive = bytes.fromhex(
        "703E8E10000000000000000042031F031E030000"
        "9F0D050010000000"
        "9F0E050010000000"
        "9F0F050010000000"
        "5A084111111111111111"
        "5F2403261231"
        "5F340101"
        "9000"
    )

    positive_out = mutations.mutate_read_record_response(positive)

    print(
        "positive READ RECORD:",
        len(positive), "->", len(positive_out),
        "bytes",
    )
    print("positive input sha256:", sha256(positive))
    print("positive output sha256:", sha256(positive_out))

    assert positive_out != positive, "Expected the valid fixture to mutate."
    assert len(positive_out) == len(positive), (
        "READ RECORD mutation unexpectedly changed record length."
    )
    assert positive_out[-2:] == b"\x90\x00", (
        f"Status word changed: {positive_out[-2:].hex().upper()}"
    )

    before = positive[:-2]
    after = positive_out[:-2]

    expected_cvm = bytes.fromhex(
        "000000000000000000001F031E030000"
    )
    assert tlv.find_tlv(after, 0x8E) == expected_cvm

    for tag in (0x9F0D, 0x9F0E, 0x9F0F):
        value = tlv.find_tlv(after, tag)
        assert value is not None, f"Tag 0x{tag:X} disappeared."
        assert value == b"\x00" * len(value), (
            f"Tag 0x{tag:X} was not zeroed."
        )

    for tag in (0x5A, 0x5F24, 0x5F34):
        assert tlv.find_tlv(after, tag) == tlv.find_tlv(before, tag), (
            f"Protected/unrelated tag 0x{tag:X} changed."
        )

    print("valid READ RECORD mutation: PASS")

    # 4. Direct low-level replacement regression.
    direct = tlv.replace_tlv(before, 0x8E, expected_cvm)
    assert len(direct) == len(before)
    assert tlv.find_tlv(direct, 0x8E) == expected_cvm

    for tag in (0x9F0D, 0x9F0E, 0x9F0F, 0x5A, 0x5F24, 0x5F34):
        assert tlv.find_tlv(direct, tag) is not None, (
            f"Tag 0x{tag:X} disappeared during direct replacement."
        )

    print("direct replace_tlv preservation: PASS")

    # 5. Historical malformed replay fixture is deliberately NOT modified.
    # The correct result is safe rejection or byte-for-byte unchanged output.
    malformed = bytes.fromhex(
        "7081BE9F420208265F25032512015F24033012315A085355222091779157"
        "5F3401009F0702FFC09F080200028C279F02069F03069F1A0295055F2A02"
        "08409A039C019F37049F35019F45029F4C089F34039F21039F7C148D12"
        "910A8A0295059F37049F4C089F02068E1B470848000B47084800001F031E"
        "0300009F51039F37049F5B0CDF6008DF6108DF6201DF63A09F0D050000000000"
        "9F0E0500000000009F0F0500000000005F28020826570E5355222091779157"
        "D301222106109F4A01829000"
    )

    try:
        malformed_out = mutations.mutate_read_record_response(malformed)
    except (ValueError, RuntimeError) as exc:
        print(
            "historical malformed fixture:",
            f"SAFE REJECTION ({type(exc).__name__}: {exc})",
        )
    else:
        assert malformed_out == malformed, (
            "Malformed fixture was transformed instead of rejected/unchanged."
        )
        assert len(malformed_out) == len(malformed)
        print("historical malformed fixture: SAFE UNCHANGED")

    print("CORE MUTATION SYNC: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print("CORE MUTATION SYNC: FAIL")
        print(f"AssertionError: {exc}")
        raise
    except Exception as exc:
        print("CORE MUTATION SYNC: ERROR")
        print(f"{type(exc).__name__}: {exc}")
        traceback.print_exc()
        raise
