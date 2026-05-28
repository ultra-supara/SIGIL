from sigil.assess.capabilities import capability_for_symbol


def test_capability_mapping():
    assert capability_for_symbol("connect") == "network"
    assert capability_for_symbol("openat") == "file_read"
    assert capability_for_symbol("dlopen") == "dynamic_loading"
    assert capability_for_symbol("getenv") == "environment_access"
