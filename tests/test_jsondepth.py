"""The explicit JSON depth limit behaves the same on every Python version."""

import pytest

from mcp_auth_doctor import _jsondepth
from mcp_auth_doctor._jsondepth import MAX_JSON_DEPTH, JSONTooDeepError, json_depth

DEEP = [
    "[" * 100000,
    "[" * 100000 + "]" * 100000,
    '{"a":' * 5000 + "1" + "}" * 5000,
]


@pytest.mark.parametrize("text", DEEP)
def test_deep_input_is_refused_before_parsing(text):
    with pytest.raises(JSONTooDeepError, match="nested"):
        _jsondepth.loads(text)


def test_too_deep_is_still_a_recursion_error():
    assert issubclass(JSONTooDeepError, RecursionError)


def test_input_at_the_limit_parses():
    text = "[" * MAX_JSON_DEPTH + "]" * MAX_JSON_DEPTH
    assert json_depth(text) == MAX_JSON_DEPTH
    assert isinstance(_jsondepth.loads(text), list)


def test_brackets_inside_strings_do_not_count():
    text = '{"a": "' + "[" * 10000 + '\\"{{{", "b": [1, {"c": "]]]"}]}'
    assert json_depth(text) == 3
    assert _jsondepth.loads(text)["b"][1]["c"] == "]]]"


def test_bytes_are_accepted():
    assert _jsondepth.loads(b'{"a": [1]}') == {"a": [1]}
