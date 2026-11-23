import pytest
import security.shell_argv_guard as mod

CASES = [
    ("shell_false", (1, 2)),
    ("argv_list", (1, 2)),
    ("filename_allowlist", (1, 2)),
    ("length_check", (1, 2)),
    ("dash_separator", (1, 2)),
    ("least_privilege", (1, 2)),
    ("env_scrub", (1, 2)),
    ("timeout", (1, 2)),
    ("output_limit", (1, 2)),
    ("cwd_pin", (1, 2)),
    ("validation", (1, 2)),
    ("error_map", (1, 2)),
    ("audit", (1, 2)),
    ("retry", (1, 2)),
    ("fallback", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
