"""Negative control for the MCP field readers.

Without this, `_mcp_compat.is_error` could quietly degrade the way the raw
attribute access did: return False for everything and let every caller pass.
An error result MUST make it answer True on the installed MCP major.
"""
import mcp.types as types
import pytest

from _mcp_compat import input_schema, is_error


def _result(error: bool):
    """Build a CallToolResult under whichever field name this major uses."""
    for field in ("is_error", "isError"):
        try:
            built = types.CallToolResult(content=[], **{field: error})
        except Exception:
            continue
        if bool(built.model_dump(by_alias=True).get("isError")) == error:
            return built
    pytest.fail("cannot construct a CallToolResult carrying isError on this MCP")


def test_is_error_separates_an_error_result_from_a_successful_one():
    assert is_error(_result(True))
    assert not is_error(_result(False))


def test_input_schema_is_read_by_its_wire_name():
    tool = types.Tool(name="probe", inputSchema={"type": "object", "properties": {}})
    assert input_schema(tool)["properties"] == {}


def test_unknown_result_shape_raises_instead_of_defaulting():
    with pytest.raises(TypeError):
        is_error(object())


def test_content_sequence_without_an_error_channel_reads_as_no_error():
    assert not is_error([])


@pytest.mark.parametrize("payload", [
    {"isError": True, "content": []},
    {"is_error": True, "content": []},
])
def test_mapping_result_carrying_the_flag_is_read_not_assumed(payload):
    # The first version of the helper grouped dict with the content sequences, so a
    # mapping that said "error" read as success. That is the silent default this
    # module removes, so it needs its own control.
    assert is_error(payload)


def test_mapping_without_an_error_channel_reads_as_no_error():
    assert not is_error({"content": []})
