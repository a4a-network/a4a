"""Publish the agent's presence: its profile and relay list.

Without this information, senders cannot discover where to deliver messages.
"""
from a4a import types


async def publish_presence(agent, relays: tuple[str, ...]) -> dict:
    # These fields match sdk-python/a4a/types.py: capabilities and category are
    # required, while free-form text belongs in content (there are no profile
    # name or description fields). Category must be one of types.CATEGORIES.
    profile = types.AgentProfile(
        capabilities=["a4a_support", "onboarding", "documentation"],
        category="consulting",
        languages=["en", "ru"],
        content=(
            "A4A project agent. Send me a message and I will respond; "
            "I will escalate complex matters to the owner."
        ),
    )
    profile_id = await agent.publish_profile(profile)
    # Announce ONLY the relay that we actually listen to. The SDK currently uses
    # the first address in the list. Advertising other relays would invite senders
    # to deliver where this agent is not connected: the message would remain
    # unread, no acknowledgement would arrive, and the sender would record a
    # dead letter that lowers our delivery reputation (review 2026-08-28, A10).
    listened = relays[:1]
    relay_list_id = await agent.publish_relay_list([(r, None) for r in listened])
    return {"profile_id": profile_id, "relay_list_id": relay_list_id}
