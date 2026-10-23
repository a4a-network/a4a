"""Read MCP result fields by their wire names instead of a Python attribute.

MCP 2.x renamed the Python fields (`isError` -> `is_error`, `inputSchema` ->
`input_schema`) while keeping the wire keys unchanged. A test that reads
`getattr(result, "isError", False)` therefore gets the DEFAULT on 2.x: it
accepts an error result as success, and no state of the system makes it fail.
That is the failure this module exists to prevent, so read the serialized
alias, which answers the same on both majors.
"""
from collections.abc import Mapping


def is_error(result) -> bool:
    """True when the tool call reported an error, on MCP 1.x and 2.x alike.

    Four shapes reach this. A `CallToolResult` carries the flag and serializes it
    under the wire name on both majors. Some paths hand back the model without a
    dump. FastMCP 1.x is annotated `Sequence[ContentBlock] | dict[str, Any]`: a
    sequence has no error channel and raises on failure, so "no error" is honest
    there, but a MAPPING can carry the wire flag and must be read, not assumed.
    Anything else raises rather than defaulting.

    The mapping branch exists because the first version of this helper grouped
    `dict` with the sequences, so `{"isError": True}` read as success — the very
    silent default this module was written to remove, reproduced inside the fix
    for it. Keep every branch explicit about whether a flag was found or absent.
    """
    dump = getattr(result, "model_dump", None)
    if callable(dump):
        return bool(dump(by_alias=True).get("isError"))
    for name in ("is_error", "isError"):
        if hasattr(result, name):
            return bool(getattr(result, name))
    if isinstance(result, Mapping):
        for name in ("isError", "is_error"):
            if name in result:
                return bool(result[name])
        return False
    if isinstance(result, (list, tuple)):
        return False
    raise TypeError(f"cannot read an error flag from {type(result).__name__}")


def input_schema(tool) -> dict:
    """The tool's JSON schema, read by its wire name on both majors."""
    return tool.model_dump(by_alias=True)["inputSchema"]
