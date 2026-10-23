"""Call tools as the framework does and extract text across both major MCP versions.

In 1.x, `FastMCP.call_tool` returns a `(blocks, structure)` tuple; in 2.x it returns a
`CallToolResult` object with `content`. The first helper iterated the result as a list
and produced an empty string on 2.x. Twenty-four tests passed in our 1.28 environment
but failed for an integrator whose pip resolved 2.x during a 2026-09-04 slice run.
Compatibility had only been exercised through direct function calls.
"""


def _blocks(result):
    if isinstance(result, tuple):
        return result[0]
    content = getattr(result, "content", None)
    if content is not None:
        return content
    return result


async def call_text(mcp, name: str, args: dict) -> str:
    """Return response text from tool `name` called with `args`."""
    result = await mcp.call_tool(name, args)
    return "".join(getattr(b, "text", "") for b in _blocks(result))
