"""A4A server entry point: stdio (default) or HTTP, plus owner commands.

An environment variable selects transport because host platforms differ. Claude
Code and Cursor launch a local stdio process, while a platform with one gateway
for all agents may support only HTTP. An integrator confirmed on 2026-09-05 that
their agents use one HTTP MCP gateway and may ignore per-user stdio configuration.
The tools remain identical; only transport changes.

    A4A_MCP_TRANSPORT=stdio        # default
    A4A_MCP_TRANSPORT=http         # MCP streamable HTTP
    A4A_MCP_HOST=127.0.0.1         # listen locally unless explicitly changed
    A4A_MCP_PORT=8765
    A4A_MCP_PATH=/mcp
    A4A_MCP_STATELESS=1            # each request is independent
    A4A_MCP_JSON=1                 # plain JSON response instead of SSE

HTTP defaults to stateless JSON because an HMAC-signing gateway typically keeps no
session and does not parse SSE. Set the same variables to ``0`` when the client
supports sessions and streaming.

HTTP transport does not authenticate callers by itself. Anyone who reaches the
port controls an agent that holds keys. Bind to ``127.0.0.1`` and place a gateway
that verifies a signature or token in front of the server.

Commands:

    python -m a4a_mcp                     # run with the configured transport
    python -m a4a_mcp issue-mandate       # sign an agent mandate with the owner key
    python -m a4a_mcp address             # show the agent address (pubkey/apub)
"""
import asyncio
import argparse
import contextlib
import json
import pathlib
import os
import sys

mcp = None


def _load_server():
    global mcp
    if mcp is None:
        from .server import mcp as server
        mcp = server
    return mcp


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


def _http_options() -> dict:
    return {
        "host": os.environ.get("A4A_MCP_HOST", "127.0.0.1"),
        "port": int(os.environ.get("A4A_MCP_PORT", "8765")),
        "streamable_http_path": os.environ.get("A4A_MCP_PATH", "/mcp"),
        "stateless_http": _env_flag("A4A_MCP_STATELESS", True),
        "json_response": _env_flag("A4A_MCP_JSON", True),
    }


def _run_http() -> None:
    """Run streamable HTTP across both major ``mcp`` package versions.

    In 2.x, ``run_streamable_http_async(**opts)`` accepts configuration directly.
    In 1.x it takes no arguments and the same fields live in ``mcp.settings``.
    Attempt direct arguments first and use the exception for compatibility because
    2.x does not expose a reliable version marker.
    """
    _load_server()
    opts = _http_options()
    print(f"A4A MCP: streamable-http at http://{opts['host']}:{opts['port']}"
          f"{opts['streamable_http_path']} (stateless={opts['stateless_http']}, "
          f"json={opts['json_response']})", file=sys.stderr, flush=True)
    try:
        asyncio.run(mcp.run_streamable_http_async(**opts))          # mcp 2.x
        return
    except TypeError:
        pass
    settings = getattr(mcp, "settings", None)                        # mcp 1.x
    if settings is None:
        raise RuntimeError("this `mcp` package accepts HTTP configuration through no "
                           "known interface; upgrade mcp or use stdio")
    for key, value in opts.items():
        setattr(settings, key, value)
    mcp.run(transport="streamable-http")


def cli_main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ('connect', 'doctor', 'rollback'):
        from .setup_cli import cli
        raise SystemExit(cli(argv))
    if argv and argv[0] == "connect-plan":
        _connect_plan(argv[1:])
        return
    if argv and argv[0].startswith("wake-"):
        _wake_admin(argv)
        return
    if argv and argv[0] in ("issue-mandate", "address", "owner-separate"):
        try:
            _admin(argv)
        except ValueError as exc:
            raise SystemExit(f"A4A owner: {exc}") from None
        return
    if argv and argv[0] in ("setup", "allow-peer", "inbox-requests"):
        _onboarding_cli(argv)
        return
    if argv:
        _inbox_admin(argv)
        return
    transport = os.environ.get("A4A_MCP_TRANSPORT", "stdio").strip().lower()
    _load_server()
    channel = os.environ.get("A4A_MCP_CHANNEL", "").strip().lower()
    if channel:
        if channel != "claude" or transport not in ("", "stdio"):
            raise SystemExit("A4A_MCP_CHANNEL supports only claude over stdio")
        from . import inbox_runtime
        from .channel import run_channel
        from a4a.inbox import InboxError
        try:
            with inbox_runtime.open_runtime():
                pass
            asyncio.run(run_channel(mcp, inbox_runtime.notices()))
        except InboxError as exc:
            raise SystemExit(f"A4A inbox: {exc}") from exc
        return
    if transport in ("http", "streamable-http", "streamable_http"):
        _run_http()
    elif transport in ("", "stdio"):
        mcp.run(transport="stdio")
    elif transport == "sse":
        mcp.run(transport="sse")
    else:
        raise SystemExit(f"A4A_MCP_TRANSPORT={transport!r} is unsupported: stdio | http | sse")


def _connect_plan(argv):
    from pathlib import Path
    from .onboarding import connection_plan
    parser = argparse.ArgumentParser(prog="python -m a4a_mcp connect-plan", allow_abbrev=False)
    parser.add_argument("--client", required=True, choices=("claude-code", "codex", "cursor", "kimi", "kimi-code", "gemini", "antigravity", "agy", "generic"))
    parser.add_argument("--home", required=True)
    parser.add_argument("--relay", required=True)
    parser.add_argument("--consumer", required=True)
    parser.add_argument("--host-executable")
    parser.add_argument("--format", choices=("json", "config"), default="json",
                        help="JSON plan, or a project configuration fragment for Codex/Cursor")
    args = parser.parse_args(argv)
    try:
        result = connection_plan(client=args.client, home=args.home, relay=args.relay,
            consumer=args.consumer, project=str(Path.cwd()), executable=sys.executable,
            host_executable=args.host_executable)
    except ValueError as exc:
        raise SystemExit(f"A4A connection plan: {exc}") from None
    if args.format == "config":
        config = result["host_configuration"]
        if config is None:
            raise SystemExit("A4A connection plan: --format config requires codex or cursor")
        # Configuration files use UTF-8, including on Windows with a legacy console codepage.
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(config["content"], end="")
    else:
        print(json.dumps(result, ensure_ascii=True))


def _quiet_poll_logs() -> None:
    """Suppress per-request polling logs from transport libraries.

    The long-running receiver polls once per interval. At INFO, httpx logs EVERY
    request with recipient and cursor: 1.1 MiB over 17 hours on an empty channel,
    measured on 2026-09-08 without rotation. WARNING keeps transport failures
    visible; silencing those would trade noise for an operational blind spot.

    This reduces VOLUME on a healthy channel but does NOT bound file size. During a
    long outage, one WARNING per attempt still grows indefinitely (review finding
    2026-09-09). Rotation or a file cap remains separate work; this change removes
    healthy-operation noise rather than solving log growth itself.
    """
    import logging

    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)


def _exit_for_delivery(result):
    """Exit code of deliver/reply for wrappers that read codes, not text (a project agent, 26.09:
    a refusal "nothing was sent" exited 0 and would count as a sent letter).
    0 acknowledged; 3 sent but not yet acknowledged (dead_letter); 1 nothing sent;
    4 unknown (see _run_delivery) - do not resend."""
    text = result if isinstance(result, str) else ""
    if text.startswith("Private delivery: acknowledged"):
        return
    raise SystemExit(3 if text.startswith("Private delivery: SENT, NOT YET CONFIRMED") else 1)


def _run_delivery(coroutine, emit):
    """Run deliver/reply; a failure exits 1 only when it is known that nothing was sent.

    Representative, 26.09: the SDK records "interrupted" (sent, then stopped) and re-raises,
    and an uncaught error exited 1 - "nothing sent" - so a wrapper reading codes would send
    the letter again. A relay refusal before any publication is "nothing sent" (1); checks
    that refuse before sending keep their own messages (1); anything else is unknown (4)."""
    from a4a.inbox import InboxError
    from a4a.relay import RelayError
    try:
        return asyncio.run(coroutine)
    except RelayError as exc:
        emit({"result": f"Private delivery: NOT SENT - no relay accepted the letter: {exc}"})
        raise SystemExit(1) from None
    except (InboxError, ValueError):
        raise
    except Exception as exc:  # noqa: BLE001 - every other failure is reported as unknown
        emit({"result": "Private delivery: UNKNOWN - the letter may or may not have gone out; "
                        f"do not resend; look at outbox-list (last entry). Cause: {type(exc).__name__}: {exc}"})
        raise SystemExit(4) from None


def _inbox_admin(argv):
    from a4a.inbox import InboxError
    from a4a.outbox import OutboxError
    from . import inbox_runtime
    parser = argparse.ArgumentParser(prog="python -m a4a_mcp")
    commands = parser.add_subparsers(dest="command", required=True)
    config = commands.add_parser("inbox-configure")
    config.add_argument("--consumer", required=True)
    config.add_argument("--ack-on-receipt", action="store_true",
                        help="confirm 'received' to allowed senders as soon as a letter is stored")
    config.add_argument("--allow-peer", action="append", default=[])
    config.add_argument("--allow-owner", action="append", default=[],
                        help="trust agents with a current mandate signed by this owner key")
    config.add_argument("--start-after", type=int)
    config.add_argument("--replace", action="store_true")
    commands.add_parser("inbox-status")
    commands.add_parser("dialogue-enable")
    next_letter = commands.add_parser(
        "inbox-next",
        description=("Take the next letter. Every result names content_chars and "
                     "content_sha256, so a cut print is visible."))
    next_letter.add_argument(
        "--content-file",
        help=("write the letter's text to this file in full and print only its path and "
              "length - nothing to cut by printing (26.09.2026: four tails looked lost)"))
    reread = commands.add_parser(
        "inbox-read",
        description=("Write a letter already taken (not pending) to a file again, in full. "
                     "The stored envelope stays after processing, so a cut print loses nothing."))
    reread.add_argument("--seq", type=int, required=True)
    reread.add_argument("--out", required=True)
    unknown = commands.add_parser(
        "inbox-unknown",
        description=("Show only seq and inner_id for legacy inbox messages in the "
                     "unknown state. This bounded local command exposes no text, "
                     "envelope, keys, or lease data."))
    unknown.add_argument("--limit", type=int, default=100,
                         help="return 1..100 records; default 100")
    done = commands.add_parser("inbox-complete")
    done.add_argument("--seq", required=True, type=int)
    done.add_argument("--lease-token", required=True)
    done.add_argument("--status", required=True, choices=("processed", "failed"))
    release = commands.add_parser(
        "inbox-release",
        description=("Return a claimed message to pending while its lease is live, "
                     "without an ACK. Only when it was certainly not handed on; after "
                     "the lease expires use inbox-reconcile."))
    release.add_argument("--seq", required=True, type=int)
    release.add_argument("--lease-token", required=True)
    reconcile = commands.add_parser(
        "inbox-reconcile",
        description=("Explicitly resolve a message whose lease expired. retry may "
                     "reissue only unexpired work from an authorized sender; "
                     "processed or failed closes it without a network ACK. Nothing "
                     "is inferred automatically; exact seq and inner_id are required."))
    reconcile.add_argument("--seq", required=True, type=int)
    reconcile.add_argument("--inner-id", required=True)
    reconcile.add_argument("--resolution", required=True,
                           choices=("retry", "processed", "failed"))
    reconcile.add_argument(
        "--send-ack", action="store_true",
        help=("with processed/failed: also tell the sender - only when you KNOW the outcome "
              "(26.09.2026: a processed letter stayed 'unconfirmed' at the sender)"))
    # Inbox pruning is an OWNER action. Both arguments are required with no defaults;
    # a default would mean "delete something," which must never happen implicitly.
    # The export is written before deletion and always exists, even when empty.
    prune = commands.add_parser(
        "inbox-prune",
        # Preserve paragraphs because the conditions are the essential part.
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Export completed messages older than the selected age. By default this "
            "deletes and changes NOTHING: messages and states remain in place. The "
            "export contains signed encrypted envelopes as stored, but the export, "
            "its metadata, and its completeness are not themselves signed. It is a "
            "content copy, not an attested document. Crash durability is UNPROVEN, "
            "so source messages remain stored."),
        epilog=(
            "EXACTLY WHAT IS EXPORTED. A row is included only when all three conditions "
            "hold: state is processed, failed, or expired; the envelope is nonempty "
            "(not previously compacted); RECEIPT time precedes the cutoff.\n"
            "\n"
            "Age is measured from when this inbox RECEIVED the message, not author "
            "creation time, work completion, or a retention value inside the message. "
            "The day count defines only the receipt cutoff.\n"
            "\n"
            "Never exported even when old enough: pending work; processing work; "
            "unknown work with an expired lease; messages blocked by the contact list "
            "because that contact may later be authorized; and messages whose time has "
            "elapsed but whose state is not yet expired. Normal inbox operations set "
            "states; export must not hide that transition.\n"
            "\n"
            "Report fields: exported is rows copied; compacted is rows emptied (always "
            "0 for export-only); bytes is envelope bytes released; mode is export-only "
            "or compact.\n"
            "\n"
            "Warning: compaction returns BYTES but not SLOTS under the max_items cap. "
            "Completion markers remain to prevent reaccepting the same message and "
            "performing its work twice."))
    prune.add_argument("--older-than-days", type=int, required=True,
                       help=("age in days from now, measured by RECEIPT time; the "
                             "cutoff is calculated here"))
    prune.add_argument("--archive", required=True,
                       help="export path; an existing file is NEVER overwritten")
    prune.add_argument("--compact", action="store_true",
                       help=("empty exported envelopes. Currently REFUSED on every "
                             "platform because export crash durability is unproven; "
                             "destructive compaction cannot rely on an unverified promise"))
    outbox_list = commands.add_parser(
        "outbox-list",
        description=("Show the sender-side delivery journal: ids, states, categories and counts "
                     "only, never envelopes. Without --state, every record."))
    outbox_list.add_argument("--state", action="append",
                             choices=("sending", "acknowledged", "dead_letter",
                                      "publish_failed", "interrupted"))
    outbox_list.add_argument("--category",
                             choices=("fact", "money", "promise", "user_data",
                                      "internal_metrics", "routine_dev"),
                             help="filter by outbound registry category")
    outbox_list.add_argument("--recipient", help="filter by recipient 64-hex or apub1... address")
    outbox_list.add_argument("--commitments-only", action="store_true",
                             help="show only restricted commitment/financial/data categories")
    outbox_list.add_argument("--limit", type=int, default=100)
    commands.add_parser(
        "outbox-summary",
        description=("Counts of the delivery journal with the moment they were taken: total, "
                     "unconfirmed (rechecks still running), unconfirmed_final, not_delivered, "
                     "plus breakdown by_category and commitments_count."))
    set_trust = commands.add_parser(
        "set-trust",
        description=("Owner command: set trust level (1=manual, 2=autonomous routine, "
                     "3=scoped autonomous), origin label, and allowed topics for a peer."))
    set_trust.add_argument("--peer", required=True, help="Peer 64-hex or apub1... address")
    set_trust.add_argument("--trust-level", type=int, required=True, choices=(1, 2, 3))
    set_trust.add_argument("--origin", choices=("external_contact", "own_developer",
                                                "scoped_partner", "owner_agent"))
    set_trust.add_argument("--topic", action="append", default=[],
                           help="Allowed topic for L3 scoped autonomy (may be repeated)")
    set_trust.add_argument("--remote-attested", action="store_true",
                           help="Confirm that the remote peer also granted L3 on the shared topic")
    approve_send = commands.add_parser(
        "approve-send",
        description=("Owner command: issue a single-use send permit for an L1 peer or a "
                     "restricted outbound category (money, promise, user_data, internal_metrics)."))
    approve_send.add_argument("--to", required=True, help="Recipient 64-hex or apub1... address")
    approve_send.add_argument("--text", help="Exact message text approved for sending")
    approve_send.add_argument("--text-file", help="File containing exact message text approved for sending")
    approve_send.add_argument("--sha256", help="SHA-256 hex digest of approved message text")
    approve_send.add_argument("--category", choices=("fact", "money", "promise", "user_data",
                                                     "internal_metrics", "routine_dev"))
    approve_send.add_argument("--ttl", type=int, default=3600,
                              help="Permit validity in seconds (60..604800, default 3600)")
    file_status = commands.add_parser(
        "file-status", description=("Ask this mailbox's file gateway whether a sent file was "
                                    "fetched: stored, fetched, expired_unfetched or "
                                    "expired_fetched."))
    file_status.add_argument("--sha256", required=True)
    outbox_recheck = commands.add_parser(
        "outbox-recheck", description="Look again for the recipient's ACK of one delivery.")
    outbox_recheck.add_argument("--delivery-id", required=True)
    outbox_republish = commands.add_parser(
        "outbox-republish",
        description=("Publish the journaled envelope of one unacknowledged delivery again, "
                     "byte for byte. Bounded to five times per delivery."))
    outbox_republish.add_argument("--delivery-id", required=True)
    deliver = commands.add_parser(
        "deliver",
        description=("Reliable private delivery to an allowed contact, exactly like MCP "
                     "a4a_deliver: gift wrap, recipient ACK, journaled. For sessions that "
                     "have no A4A MCP tools. Prefer --text-file for non-ASCII text."))
    deliver.add_argument("--to", required=True, help="recipient public key, 64 hex or apub1...")
    deliver.add_argument("--conversation-id", default="",
                         help="optional 64-hex conversation handle, encrypted inside the gift wrap")
    deliver.add_argument("--new-letter", action="store_true",
                         help="state that this is a new letter, not an answer; required "
                              "from 2026-10-11 (answer letters with reply)")
    deliver.add_argument("--category", default="routine_dev",
                         choices=("fact", "money", "promise", "user_data",
                                  "internal_metrics", "routine_dev"))
    deliver.add_argument("--topic", default="", help="topic tag for L3 topic-scoped peers")
    deliver.add_argument("--owner-approval-token", default="",
                         help="single-use permit token issued by approve-send")
    deliver.add_argument("--owner-approved", action="store_true",
                         help="explicit owner approval flag for L1 or restricted categories")
    deliver.add_argument("--commitment-note", default="",
                         help="short non-secret note for the outbound registry")
    body = deliver.add_mutually_exclusive_group(required=True)
    body.add_argument("--text")
    body.add_argument("--text-file")
    reply = commands.add_parser(
        "reply",
        description=("Answer letter --seq of this mailbox, exactly like MCP a4a_reply: the "
                     "sender and the letter's ids come from the mailbox, the answer carries "
                     "a signed reference to the letter, delivery is journaled. The letter "
                     "must have been read once (inbox-next); no lease is needed."))
    reply.add_argument("--seq", required=True, type=int)
    reply.add_argument("--category", default="routine_dev",
                       choices=("fact", "money", "promise", "user_data",
                                "internal_metrics", "routine_dev"))
    reply.add_argument("--topic", default="", help="topic tag for L3 topic-scoped peers")
    reply.add_argument("--owner-approval-token", default="",
                       help="single-use permit token issued by approve-send")
    reply.add_argument("--owner-approved", action="store_true",
                       help="explicit owner approval flag for L1 or restricted categories")
    reply.add_argument("--commitment-note", default="",
                       help="short non-secret note for the outbound registry")
    reply_body = reply.add_mutually_exclusive_group(required=True)
    reply_body.add_argument("--text")
    reply_body.add_argument("--text-file")
    watch = commands.add_parser("inbox-watch")
    lifetime = watch.add_mutually_exclusive_group()
    lifetime.add_argument("--once", action="store_true")
    lifetime.add_argument("--duration", type=int, default=3600)
    lifetime.add_argument("--forever", action="store_true",
                          help="observe without a lifetime limit until stopped; installs no service")
    create_invite = commands.add_parser(
        "create-invite",
        description=("Create a one-time expiring invitation link (https://a4a.network/i/<id>#<secret>) "
                     "so the remote agent can complete a mutual A4A handshake in one step at L1."))
    create_invite.add_argument("--ttl", type=int, default=86400,
                               help="Invitation lifetime in seconds (60..604800, default 86400)")
    create_invite.add_argument("--label", default="",
                               help="Optional human label encrypted inside the invitation card")
    create_invite.add_argument("--base-url", default="https://a4a.network/i")
    accept_invite = commands.add_parser(
        "accept-invite",
        description=("Redeem a one-time invitation link, admit the inviter at Trust Level L1 "
                     "(external_contact), and send back the signed handshake."))
    accept_invite.add_argument("--url", required=True,
                               help="Full invitation URL including the #<secret> fragment")
    accept_invite.add_argument("--intro", default="",
                               help="Optional short introduction note")
    check_invite = commands.add_parser(
        "check-invite",
        description="Check one or all invitations and finalize any pending rendezvous acceptances.")
    check_invite.add_argument("--invite-id", help="Specific invite_id to check")
    revoke_invite = commands.add_parser(
        "revoke-invite",
        description="Revoke an open one-time invitation locally and overwrite its card on relays.")
    revoke_invite.add_argument("--invite-id", required=True)
    list_invites = commands.add_parser(
        "list-invites",
        description="List one-time invitations created by this mailbox.")
    list_invites.add_argument("--include-url", action="store_true")
    intake_mode = commands.add_parser(
        "set-intake-mode",
        description="Set intake mode for unrecognized senders: closed, reception, or public_service.")
    intake_mode.add_argument("--mode", required=True,
                             choices=("closed", "reception", "public_service"))
    q_list = commands.add_parser(
        "quarantine-list",
        description="Show digest of quarantined reception inquiries (Trust Level L0).")
    q_list.add_argument("--state", default="pending",
                        choices=("pending", "accepted", "rejected", "blocked", "all"))
    q_list.add_argument("--limit", type=int, default=50)
    q_decide = commands.add_parser(
        "quarantine-decide",
        description="Apply owner decision to a quarantined inquiry: accept (promote to L1), reject, or block.")
    q_decide.add_argument("--req-id", type=int, required=True)
    q_decide.add_argument("--decision", required=True, choices=("accept", "reject", "block"))
    args = parser.parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
        sys.stdout.reconfigure(encoding="utf-8")

    def emit(value):
        print(json.dumps(value, ensure_ascii=False), flush=True)

    async def observe():
        if args.once:
            from a4a.inbox_receiver import InboxReceiver
            with inbox_runtime.open_runtime() as (policy, agent, store):
                receiver = InboxReceiver(
                    agent, store,
                    lambda: inbox_runtime.refresh_policy(policy).allowed_peers,
                    start_after=policy.start_after,
                    ack_on_receipt=policy.ack_on_receipt,
                    allowed_owners=lambda: inbox_runtime.refresh_policy(policy).allowed_owners,
                    intake_mode=lambda: inbox_runtime.refresh_policy(policy).intake_mode,
                    blocked_senders=lambda: inbox_runtime.refresh_policy(policy).blocked_senders,
                    inband_authorizer=inbox_runtime.try_redeem_inband_invitation,
                )
                async def flush_acks():
                    await inbox_runtime._flush_completion_acks(policy, agent, store)
                    await inbox_runtime._recheck_sent_deliveries(agent)
                hint = await receiver.notice_once(interval=policy.notify_interval,
                                                   per_hour=policy.notify_per_hour,
                                                   on_tick=flush_acks)
                if hint:
                    emit(hint)
            return
        if not args.forever and not 1 <= args.duration <= 86400:
            raise InboxError("observer duration must be 1..86400 seconds")
        try:
            async with asyncio.timeout(None if args.forever else args.duration):
                async with contextlib.aclosing(inbox_runtime.notices()) as source:
                    async for hint in source:
                        emit(hint)
        except TimeoutError:
            print("A4A inbox: bounded observation finished", file=sys.stderr)

    try:
        if args.command == "inbox-configure":
            policy = inbox_runtime.configure(args.consumer, args.allow_peer,
                                               start_after=args.start_after, replace=args.replace,
                                               ack_on_receipt=args.ack_on_receipt,
                                               allowed_owners=args.allow_owner)
            emit({"state": "configured", "consumer": policy.consumer,
                  "recipient": policy.recipient, "allowed_peers": sorted(policy.allowed_peers),
                  "allowed_owners": sorted(policy.allowed_owners),
                  "relay": policy.relay, "start_after": policy.start_after,
                  "ack_on_receipt": policy.ack_on_receipt})
        elif args.command == "inbox-status":
            emit(inbox_runtime.status())
        elif args.command == "inbox-next":
            taken = asyncio.run(inbox_runtime.claim_authorized())
            message = taken.get("message")
            if args.content_file and message:
                pathlib.Path(args.content_file).write_text(
                    message.pop("content"), encoding="utf-8", newline="\n")
                message["content_file"] = args.content_file
            emit(taken)
        elif args.command == "inbox-read":
            emit(inbox_runtime.reread(args.seq, args.out))
        elif args.command == "inbox-unknown":
            emit(inbox_runtime.unknown_bindings(args.limit))
        elif args.command == "inbox-complete":
            emit(asyncio.run(inbox_runtime.complete_with_ack(
                args.seq, args.lease_token, args.status)))
        elif args.command == "inbox-release":
            emit(inbox_runtime.release(args.seq, args.lease_token))
        elif args.command == "inbox-reconcile":
            result = asyncio.run(inbox_runtime.reconcile_authorized(
                args.seq, args.inner_id, args.resolution))
            if args.send_ack and args.resolution in ("processed", "failed"):
                result = {**result, **asyncio.run(inbox_runtime.send_reconciled_ack(args.seq))}
            emit(result)
        elif args.command == "dialogue-enable":
            from . import dialogue_runtime
            emit(dialogue_runtime.enable())
        elif args.command == "inbox-prune":
            emit(inbox_runtime.prune(args.older_than_days, args.archive,
                                     compact=args.compact))
        elif args.command == "inbox-watch":
            _quiet_poll_logs()
            asyncio.run(observe())
        elif args.command == "set-trust":
            policy = inbox_runtime.set_peer_trust(
                args.peer,
                level=args.trust_level,
                origin=args.origin,
                topics=args.topic,
                remote_trust_attested=args.remote_attested,
            )
            from a4a.keys import Keys
            norm = Keys.normalize_pubkey(args.peer)
            emit({"state": "trust_updated", "peer": norm,
                  "peer_policy": policy.peer_policy(norm)})
        elif args.command == "approve-send":
            if args.text_file and args.text:
                raise InboxError("pass either --text or --text-file, not both")
            approved_text = (pathlib.Path(args.text_file).read_text(encoding="utf-8")
                             if args.text_file else args.text)
            permit = inbox_runtime.grant_send_permit(
                args.to,
                text=approved_text,
                content_sha256=args.sha256,
                category=args.category,
                ttl_seconds=args.ttl,
            )
            emit({"state": "permit_issued", **permit})
        elif args.command == "create-invite":
            emit(asyncio.run(inbox_runtime.create_invitation(
                ttl_seconds=args.ttl,
                label=args.label,
                base_url=args.base_url,
            )))
        elif args.command == "accept-invite":
            emit(asyncio.run(inbox_runtime.accept_invitation(
                args.url,
                intro=args.intro,
            )))
        elif args.command == "check-invite":
            emit(asyncio.run(inbox_runtime.check_invitation(args.invite_id)))
        elif args.command == "revoke-invite":
            emit(asyncio.run(inbox_runtime.revoke_invitation(args.invite_id)))
        elif args.command == "list-invites":
            emit({"invitations": inbox_runtime.list_invitations(include_url=args.include_url)})
        elif args.command == "set-intake-mode":
            pol = inbox_runtime.set_intake_mode(args.mode)
            emit({"state": "intake_mode_updated", "intake_mode": pol.intake_mode})
        elif args.command == "quarantine-list":
            state_filter = None if args.state == "all" else args.state
            emit(inbox_runtime.quarantine_digest(state=state_filter, limit=args.limit))
        elif args.command == "quarantine-decide":
            emit(inbox_runtime.quarantine_decide(args.req_id, args.decision))
        elif args.command == "deliver":
            from . import server
            text = (pathlib.Path(args.text_file).read_text(encoding="utf-8")
                    if args.text_file else args.text)
            token = args.owner_approval_token
            if args.owner_approved and not token:
                token = inbox_runtime.grant_send_permit(
                    args.to, text=text, category=args.category)["token"]
            delivery = server.a4a_deliver(
                args.to, text, args.conversation_id,
                new_letter=args.new_letter,
                category=args.category,
                topic=args.topic,
                owner_approval_token=token,
                commitment_note=args.commitment_note,
            )
            result = _run_delivery(delivery, emit)
            emit({"result": result})
            _exit_for_delivery(result)
        elif args.command == "reply":
            from . import server
            text = (pathlib.Path(args.text_file).read_text(encoding="utf-8")
                    if args.text_file else args.text)
            token = args.owner_approval_token
            if args.owner_approved and not token:
                target = inbox_runtime.reply_target(args.seq)
                token = inbox_runtime.grant_send_permit(
                    target["to_pubkey"], text=text, category=args.category)["token"]
            result = _run_delivery(
                server.a4a_reply(
                    args.seq, text,
                    category=args.category,
                    topic=args.topic,
                    owner_approval_token=token,
                    commitment_note=args.commitment_note,
                ),
                emit,
            )
            emit({"result": result})
            _exit_for_delivery(result)
        elif args.command == "file-status":
            import re
            from a4a import file_gateway
            from . import identity
            gateway = os.environ.get("A4A_FILE_GATEWAY", "").split(",")[0].strip()
            if not gateway:
                raise SystemExit("A4A file: no file gateway is configured (A4A_FILE_GATEWAY)")
            if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
                raise SystemExit("A4A file: --sha256 must be 64 lowercase hex characters")
            try:
                emit(asyncio.run(file_gateway.status(
                    gateway, identity.load_or_create_identity(), args.sha256)))
            except file_gateway.FileGatewayError as exc:
                raise SystemExit(f"A4A file: {exc}") from exc
        elif args.command.startswith("outbox-"):
            from . import identity, outbox_runtime
            if (args.command not in ("outbox-list", "outbox-summary")
                    and not _is_delivery_id(args.delivery_id)):
                raise SystemExit(_delivery_id_problem(args.delivery_id))
            # Opening the store creates it, so a shell with the wrong A4A_HOME would
            # grow a second, empty journal and answer "no record" for real letters.
            if not outbox_runtime._journal_exists():
                raise SystemExit(
                    f"A4A outbox: no delivery journal in {identity.IDENTITY_DIR}. Nothing "
                    "was ever sent from this identity: check that A4A_HOME is the one "
                    "the letters were sent from.")
            if args.command == "outbox-summary":
                emit(outbox_runtime.summary())
            elif args.command == "outbox-list":
                if not 1 <= args.limit <= 1000:
                    raise SystemExit("A4A outbox: --limit must be 1..1000")
                recip = None
                if args.recipient:
                    from a4a.keys import Keys
                    recip = Keys.normalize_pubkey(args.recipient)
                emit(outbox_runtime.list_records(
                    args.state, args.limit,
                    category=args.category,
                    recipient=recip,
                    commitments_only=args.commitments_only,
                ))
            elif args.command == "outbox-recheck":
                record = asyncio.run(outbox_runtime.recheck(args.delivery_id))
                if record is None:
                    raise SystemExit(
                        "A4A outbox: no journal record for this delivery_id in "
                        f"{identity.IDENTITY_DIR}. The journal belongs to one identity: "
                        "check that A4A_HOME is the one the letter was sent from.")
                emit(record)
            else:
                emit(asyncio.run(outbox_runtime.republish(args.delivery_id)))
    except InboxError as exc:
        raise SystemExit(f"A4A inbox: {exc}") from exc
    except (OutboxError, ValueError) as exc:
        raise SystemExit(f"A4A outbox: {exc}") from exc


def _is_delivery_id(value):
    import re
    return re.fullmatch(r"[0-9a-f]{32}", value) is not None


def _delivery_id_problem(value):
    """Say what was given instead, so a wrong id never reads as a missing record."""
    import re
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return ("A4A outbox: this is a 64-character event_id, not a delivery_id. Pass the "
                "32-character delivery_id that deliver printed next to it.")
    return (f"A4A outbox: --delivery-id must be the full 32 lowercase hex characters "
            f"deliver printed; got {len(value)} characters.")


def _wake_admin(argv):
    from a4a.inbox import InboxError
    from .wake_runtime import run_wake
    parser = _OwnerArgumentParser(prog="python -m a4a_mcp", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("wake-run", allow_abbrev=False)
    run.add_argument("--project-id", required=True)
    run.add_argument("--target-session-id", required=True)
    run.add_argument("--token-file", required=True,
                     help="absolute private wake-only credential file; never pass the token itself")
    run.add_argument("--endpoint", default="ws://127.0.0.1:9876/")
    run.add_argument("--resume-rejected", action="store_true",
                     help="explicitly resume a corrected persistent rejection; changes no permissions")
    lifetime = run.add_mutually_exclusive_group()
    lifetime.add_argument("--once", action="store_true")
    lifetime.add_argument("--duration", type=int, default=3600)
    lifetime.add_argument("--forever", action="store_true",
                          help="ordinary receiver process until stopped; no model timer or service installation")
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(run_wake(args.project_id, args.target_session_id,
            args.token_file, endpoint=args.endpoint, once=args.once,
            duration=args.duration, forever=args.forever, resume=args.resume_rejected))
    except (InboxError, ValueError) as exc:
        raise SystemExit(f"A4A host wake: {exc}") from None
    print(json.dumps(result), flush=True)


class _OwnerArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # Invalid arguments may contain an accidentally supplied password.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid owner command arguments; use --help. Password arguments are not supported.\n")


def _admin(argv: list[str]) -> None:
    """Owner commands for issuing a mandate and showing the agent address.

    These support ``A4A_MANDATE_AUTO=0`` deployments: the owner performs setup once
    during account creation, after which the agent only publishes.
    """
    from . import identity
    from .server import _mandate_days, _relay_url, _relay_urls
    from . import owner_admin

    parser = _OwnerArgumentParser(prog="python -m a4a_mcp", allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("address")
    separate = commands.add_parser("owner-separate")
    separate.add_argument("--owner-file", required=True)
    issue_parser = commands.add_parser("issue-mandate")
    issue_parser.add_argument("--owner-file")
    issue_parser.add_argument("--days", "-d", type=int)
    args = parser.parse_args(argv)
    if getattr(args, "owner_file", None) is not None and not args.owner_file.strip():
        raise ValueError("owner file path must not be empty")

    if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
        sys.stdout.reconfigure(encoding="utf-8")
    if args.command == "owner-separate":
        owner_pubkey = owner_admin.separate_owner(
            args.owner_file, owner_admin.prompt_password(confirm=True))
        print(f"Owner key separated: {owner_pubkey}\n"
              "Keep the encrypted vault and passphrase separately; restart MCP processes.\n"
              "The vault alone does not back up the agent identity or conversation history.")
        return
    if args.command == "address":
        keys = identity.load_or_create_identity()
        print(f"pubkey (hex): {keys.pubkey_hex}\napub:         {keys.apub}\n"
              f"relay:        {_relay_url()}\nidentity:     {identity.identity_path()}")
        return

    days = args.days if args.days is not None else _mandate_days()
    if not 1 <= days <= 365:
        raise ValueError("mandate days must be 1..365")
    if args.owner_file is not None:
        owner = owner_admin.unlock_owner(args.owner_file, owner_admin.prompt_password())
    else:
        owner = identity.load_or_create_owner_identity()
    keys = identity.load_or_create_identity()

    async def issue() -> str:
        from a4a import Agent
        async with Agent(_relay_urls(), keys=keys) as agent:
            return await agent.ensure_registered(
                owner,
                name="User MCP agent", days=days,
                renew_before_days=max(1, days // 3))
    deleg_id = asyncio.run(issue())
    print(f"Mandate issued: {deleg_id}\n  agent:    {keys.pubkey_hex}\n"
          f"  owner:    {owner.pubkey_hex}\n"
          f"  lifetime: {days} days (A4A_MANDATE_DAYS)\n  relay:    {_relay_url()}")


DEMO_AGENT_APUB = "apub1jqahsu46f6gwm7husjlmvzvhggrdfugjda8gjl0tnr9wcq2z6casj59wqj"
DEFAULT_PUBLIC_RELAYS = (
    "wss://eu1.a4a.network",
    "wss://us1.a4a.network",
    "wss://sg1.a4a.network",
    "wss://ru1.a4a.network",
)


def _onboarding_cli(argv: list[str]) -> None:
    """Agent onboarding and contact-discovery helpers: setup, allow-peer, inbox-requests."""
    import time
    from a4a import Agent, AgentProfile, Keys
    from a4a.inbox import InboxError
    from a4a.sanitize import wrap_untrusted
    from . import identity, inbox_runtime
    from .server import _relay_urls

    parser = argparse.ArgumentParser(prog="python -m a4a_mcp")
    sub = parser.add_subparsers(dest="command", required=True)

    setup_p = sub.add_parser("setup", description="One-shot agent setup: keys, 30-day mandate, profile, relay list, and inbox policy.")
    setup_p.add_argument("--agent-name", default="My AI Agent")
    setup_p.add_argument("--capabilities", default="general,research,coding")
    setup_p.add_argument("--category", default="other")
    setup_p.add_argument("--languages", default="ru,en")
    setup_p.add_argument("--description", default="Personal AI Agent on A4A")
    setup_p.add_argument("--allow-peer", action="append", default=[])
    setup_p.add_argument("--consumer", default="mcp-agent")
    setup_p.add_argument("--days", type=int, default=30)

    allow_p = sub.add_parser("allow-peer", description="Add one or more apub1.../hex peers to allowed_peers and import any waiting letters from them.")
    allow_p.add_argument("peers", nargs="+", help="Peer apub1... or 64-hex address(es)")
    allow_p.add_argument("--trust-level", type=int, choices=(1, 2, 3), default=None,
                         help="Optional trust level (1=manual, 2=autonomous routine, 3=scoped autonomous)")
    allow_p.add_argument("--origin", choices=("external_contact", "own_developer",
                                              "scoped_partner", "owner_agent"))
    allow_p.add_argument("--topic", action="append", default=[],
                         help="Allowed topic(s) when --trust-level 3 is set")
    allow_p.add_argument("--remote-attested", action="store_true",
                         help="Confirm bilateral L3 attestation on the shared topic")

    req_p = sub.add_parser("inbox-requests", description="Check relays for incoming messages from senders not yet in allowed_peers (contact requests).")
    req_p.add_argument("--days", type=int, default=14, help="Lookback window in days (default: 14)")

    args = parser.parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") != "utf8":
        sys.stdout.reconfigure(encoding="utf-8")

    def emit(val):
        print(json.dumps(val, ensure_ascii=False, indent=2), flush=True)

    if args.command == "setup":
        if not os.environ.get("A4A_RELAY"):
            os.environ["A4A_RELAY"] = ",".join(DEFAULT_PUBLIC_RELAYS)
        owner = identity.load_or_create_owner_identity()
        keys = identity.load_or_create_identity()
        relays = _relay_urls()
        caps = [c.strip() for c in args.capabilities.split(",") if c.strip()] or ["general"]
        langs = [l.strip() for l in args.languages.split(",") if l.strip()] or ["en"]

        async def _run_setup():
            async with Agent(relays, keys=keys) as agent:
                deleg_id = await agent.ensure_registered(
                    owner, name=args.agent_name, days=max(1, min(365, args.days)),
                    renew_before_days=max(1, args.days // 3),
                )
                await agent.publish_profile(AgentProfile(
                    capabilities=caps,
                    category=args.category,
                    languages=langs,
                    content=args.description,
                ))
                await agent.publish_relay_list(relays)
                return deleg_id

        deleg_id = asyncio.run(_run_setup())
        existing = inbox_runtime.load_policy()
        merged_peers = set(existing.allowed_peers) if existing else set()
        merged_peers.add(Keys.normalize_pubkey(DEMO_AGENT_APUB))
        for raw_peer in args.allow_peer:
            for item in str(raw_peer).split(","):
                if item.strip():
                    merged_peers.add(Keys.normalize_pubkey(item.strip()))
        start_after = existing.start_after if existing else max(0, int(time.time()) - 300)
        policy = inbox_runtime.configure(
            args.consumer, sorted(merged_peers),
            start_after=start_after, replace=True, ack_on_receipt=True,
            allowed_owners=sorted(existing.allowed_owners) if existing else (),
        )
        emit({
            "state": "ready",
            "agent_apub": keys.apub,
            "agent_pubkey": keys.pubkey_hex,
            "owner_pubkey": owner.pubkey_hex,
            "delegation_id": deleg_id,
            "card_url": f"https://a4a.network/c/#{keys.apub}",
            "invite_prompt_en": f"Connect A4A (https://a4a.network/docs/connect-agent.txt) and message my agent {keys.apub}",
            "allowed_peers": sorted(policy.allowed_peers),
            "allowed_peers_apub": [Keys.encode_apub(p) for p in sorted(policy.allowed_peers)],
            "relays": relays,
        })
        return

    if args.command == "allow-peer":
        existing = inbox_runtime.load_policy()
        merged_peers = set(existing.allowed_peers) if existing else set()
        added_hex = set()
        for raw_peer in args.peers:
            for item in str(raw_peer).split(","):
                if item.strip():
                    norm = Keys.normalize_pubkey(item.strip())
                    merged_peers.add(norm)
                    added_hex.add(norm)
        consumer = existing.consumer if existing else "mcp-agent"
        start_after = existing.start_after if existing else max(0, int(time.time()) - 86400)
        ack_on_receipt = existing.ack_on_receipt if existing else True
        owners = sorted(existing.allowed_owners) if existing else ()
        policy = inbox_runtime.configure(
            consumer, sorted(merged_peers),
            start_after=start_after, replace=True,
            ack_on_receipt=ack_on_receipt, allowed_owners=owners,
        )
        if args.trust_level is not None:
            for norm in sorted(added_hex):
                policy = inbox_runtime.set_peer_trust(
                    norm,
                    level=args.trust_level,
                    origin=args.origin,
                    topics=args.topic,
                    remote_trust_attested=args.remote_attested,
                )

        async def _import_waiting():
            imported = 0
            with inbox_runtime.open_runtime() as (pol, agent, store):
                await agent.relay.connect()
                try:
                    outers = await agent.relay.query({
                        "kinds": [1059, 31033],
                        "#p": [agent.pubkey],
                        "since": int(time.time()) - 14 * 86400,
                    })
                    for outer in sorted(outers, key=lambda e: (e.created_at, e.id)):
                        msg = agent._decode_incoming(outer)
                        if msg and msg.get("from_pubkey") in added_hex:
                            verdict = store.accept(agent, outer, pol.allowed_peers)
                            if verdict == "stored":
                                imported += 1
                                if pol.ack_on_receipt:
                                    with contextlib.suppress( Exception ):
                                        await agent.acknowledge(msg, status="received")
                finally:
                    await agent.relay.aclose()
            return imported

        imported_count = asyncio.run(_import_waiting())
        emit({
            "state": "updated",
            "added_peers": sorted(added_hex),
            "added_peers_apub": [Keys.encode_apub(p) for p in sorted(added_hex)],
            "imported_waiting_letters": imported_count,
            "allowed_peers": sorted(policy.allowed_peers),
        })
        return

    if args.command == "inbox-requests":
        policy = inbox_runtime.active_policy()
        since = int(time.time()) - max(1, min(30, args.days)) * 86400

        async def _fetch_requests():
            async with Agent(_relay_urls(), keys=identity.load_or_create_identity()) as agent:
                msgs = await agent.read_private_messages(since=since)
                reqs = []
                seen = set()
                for m in msgs:
                    sender = m.get("from_pubkey", "")
                    if not sender or sender in policy.allowed_peers:
                        continue
                    dedup_key = (sender, m.get("delivery_id") or m.get("inner_id") or "")
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    apub = Keys.encode_apub(sender)
                    reqs.append({
                        "from_apub": apub,
                        "from_pubkey": sender,
                        "signed_at": m.get("signed_at"),
                        "delivery_id": m.get("delivery_id", ""),
                        "content": wrap_untrusted(m.get("content", ""), source=sender[:12]),
                        "approve_command": f"python -I -m a4a_mcp allow-peer {apub}",
                    })
                return reqs

        requests_list = asyncio.run(_fetch_requests())
        emit({
            "contact_requests_count": len(requests_list),
            "contact_requests": requests_list,
            "note": (
                "Ask your user whether to approve each new contact. "
                "When approved, run `python -I -m a4a_mcp allow-peer <from_apub>`, "
                "then `python -I -m a4a_mcp inbox-next` and `reply`."
            ) if requests_list else "No pending contact requests from unapproved senders.",
        })
        return


if __name__ == "__main__":
    cli_main()
