from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .chatgpt import AuthContext, ChatGPTClient
from .cpa import build_cpa, build_cpa_filename, load_json_object
from .har import analyze_har, load_har, select_pat_credential, select_session_snapshot
from .management import ManagementClient


def _default_har() -> Path:
    matches = sorted(Path.cwd().glob("*.har"))
    if len(matches) != 1:
        raise ValueError("pass --har when the current directory does not contain exactly one HAR")
    return matches[0]


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _load_auth(path: str) -> tuple[dict[str, Any], AuthContext]:
    data = load_json_object(path)
    context = AuthContext.from_mapping(data)
    return data, context


def command_analyze(args: argparse.Namespace) -> int:
    har_path = Path(args.har) if args.har else _default_har()
    report = analyze_har(load_har(har_path))
    if args.json_out:
        _write_json(Path(args.json_out), report)

    print(f"HAR: {har_path}")
    print(f"Entries: {report['entry_count']}")
    for item in report["signins"]:
        print(f"signin  #{item['index']} status={item['status']} email={item['login_hint']}")
    for item in report["invites"]:
        print(
            f"invite  #{item['index']} status={item['status']} account={item['account_id']} "
            f"body_captured={item['request_body_captured']}"
        )
    for item in report["member_deletes"]:
        print(
            f"leave   #{item['index']} status={item['status']} account={item['account_id']} "
            f"user={item['user_id']}"
        )
    for item in report["workspace_selections"]:
        print(f"select  #{item['index']} workspace={item['workspace_id']}")
    for item in report["token_creations"]:
        print(
            f"PAT     #{item['index']} status={item['status']} workspace={item['workspace_id']} "
            f"email={item['creator_email']} ttl={item['ttl']}"
        )
    print(f"Captured session snapshots: {report['session_snapshots']}")
    if report["inferences"].get("invitee_email"):
        print(f"Inferred invitee: {report['inferences']['invitee_email']}")
    return 0


def command_convert(args: argparse.Namespace) -> int:
    har = None
    pat_token = args.pat_token
    if args.session_json:
        session = load_json_object(args.session_json)
        source_name = Path(args.session_json).name
    else:
        har_path = Path(args.har) if args.har else _default_har()
        har = load_har(har_path)
        snapshot = select_session_snapshot(
            har,
            email=args.email,
            index=args.session_index,
            mode=args.session_selection,
        )
        session = snapshot.data
        source_name = f"{har_path.name}#entry-{snapshot.index}"
        if not pat_token:
            pat = select_pat_credential(har, email=args.email, index=args.pat_index)
            pat_token = pat.token if pat else None

    if args.refresh_live:
        context = AuthContext.from_mapping(session)
        if not context.session_token:
            raise ValueError("selected session has no sessionToken for live refresh")
        with ChatGPTClient(
            impersonate=args.impersonate,
            timeout=args.timeout,
            proxy=args.proxy,
        ) as client:
            session = client.refresh_session(
                context.session_token,
                account_id=context.account_id or None,
            )

    now = _parse_time(args.now) or datetime.now(timezone.utc)
    payload = build_cpa(session, personal_access_token=pat_token, now=now)
    email = str(payload.get("email") or "chatgpt-session")
    filename = args.filename or build_cpa_filename(email)
    if args.output:
        output = Path(args.output)
        if output.suffix.lower() != ".json" or output.is_dir():
            output = output / filename
    else:
        output = Path("output") / filename
    _write_json(output, payload)
    print(f"Source: {source_name}")
    print(f"CPA: {output.resolve()}")
    print(f"Email: {payload.get('email')}")
    print(f"Account: {payload.get('account_id')}")
    print(f"Plan: {payload.get('plan_type')}")
    print(f"PAT access token: {'yes' if payload.get('access_token') else 'no'}")
    return 0


def command_push(args: argparse.Namespace) -> int:
    api_key = args.management_key or os.environ.get("CPA_MANAGEMENT_KEY", "")
    client = ManagementClient(
        args.base_url,
        api_key,
        timeout=args.timeout,
        impersonate=args.impersonate,
    )
    result = client.push_file(
        args.file,
        remote_name=args.remote_name,
        replace=args.replace,
        dry_run=args.dry_run,
    )
    print(f"Action: {result.action}")
    print(f"File: {result.filename}")
    print(f"Verified: {result.verified}")
    print(result.message)
    return 0


def command_invite(args: argparse.Namespace) -> int:
    _, context = _load_auth(args.auth_json)
    access_token = context.access_token
    account_id = args.account_id or context.account_id
    if not access_token or not account_id:
        raise ValueError("auth JSON must provide access token and account id")
    with ChatGPTClient(impersonate=args.impersonate, timeout=args.timeout, proxy=args.proxy) as client:
        response = client.invite(access_token, account_id, args.email)
    print(json.dumps(response, ensure_ascii=False, indent=2))
    return 0


def command_leave(args: argparse.Namespace) -> int:
    _, context = _load_auth(args.auth_json)
    access_token = context.access_token
    account_id = args.account_id or context.account_id
    user_id = args.user_id or context.user_id
    if not access_token or not account_id or not user_id:
        raise ValueError("auth JSON must provide access token, account id, and user id")
    with ChatGPTClient(impersonate=args.impersonate, timeout=args.timeout, proxy=args.proxy) as client:
        response = client.leave(access_token, account_id, user_id)
    print(json.dumps(response, ensure_ascii=False, indent=2))
    return 0


def command_create_token(args: argparse.Namespace) -> int:
    data, context = _load_auth(args.auth_json)
    account_id = args.account_id or context.account_id
    name = args.name or context.email or "codex"
    if not context.access_token or not account_id:
        raise ValueError("auth JSON must provide access token and account id")
    with ChatGPTClient(impersonate=args.impersonate, timeout=args.timeout, proxy=args.proxy) as client:
        response = client.create_personal_access_token(
            context.access_token,
            account_id,
            name=name,
            ttl=args.ttl,
        )
    token = str(response.get("access_token") or "")
    safe_response = {**response, "access_token": "<written-to-output>" if token else ""}
    if args.output:
        _write_json(Path(args.output), response)
    if args.update_cpa:
        if not token:
            raise ValueError("token creation response did not contain access_token")
        data["access_token"] = token
        for legacy_key in ("session_token", "sessionToken", "expired", "headers"):
            data.pop(legacy_key, None)
        _write_json(Path(args.update_cpa), data)
    print(json.dumps(safe_response, ensure_ascii=False, indent=2))
    return 0


def command_refresh_session(args: argparse.Namespace) -> int:
    _, context = _load_auth(args.auth_json)
    account_id = args.account_id or context.account_id
    if not context.session_token:
        raise ValueError("auth JSON must provide sessionToken/session_token")
    with ChatGPTClient(impersonate=args.impersonate, timeout=args.timeout, proxy=args.proxy) as client:
        response = client.refresh_session(context.session_token, account_id=account_id or None)
    _write_json(Path(args.output), response)
    print(f"Session written: {Path(args.output).resolve()}")
    print(f"Email: {(response.get('user') or {}).get('email')}")
    print(f"Account: {(response.get('account') or {}).get('id')}")
    return 0


def command_gui(args: argparse.Namespace) -> int:
    return command_web(args)


def command_web(args: argparse.Namespace) -> int:
    from .web_console import serve_web_console

    return serve_web_console(
        port=int(getattr(args, "port", 8765)),
        open_browser=not bool(getattr(args, "no_browser", False)),
    )


def _add_live_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--impersonate", default="chrome145")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--proxy")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the local Team workflow console and use HAR/CPA protocol tools"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="extract the protocol timeline from a HAR")
    analyze.add_argument("--har")
    analyze.add_argument("--json-out")
    analyze.set_defaults(func=command_analyze)

    convert = subparsers.add_parser("convert", help="convert a HAR session or session JSON to CPA")
    source = convert.add_mutually_exclusive_group()
    source.add_argument("--har")
    source.add_argument("--session-json")
    convert.add_argument("--email")
    convert.add_argument("--session-index", type=int)
    convert.add_argument(
        "--session-selection",
        choices=["latest", "before-pat", "nearest-pat"],
        default="latest",
    )
    convert.add_argument("--pat-index", type=int)
    convert.add_argument("--pat-token")
    convert.add_argument("--refresh-live", action="store_true")
    convert.add_argument("--now", help="fixed ISO timestamp for reproducible output")
    convert.add_argument("--filename")
    convert.add_argument("--output")
    _add_live_options(convert)
    convert.set_defaults(func=command_convert)

    push = subparsers.add_parser("push", help="idempotently upload a CPA JSON to management API")
    push.add_argument("--file", required=True)
    push.add_argument("--base-url", default="https://management.example.com")
    push.add_argument("--management-key")
    push.add_argument("--remote-name")
    push.add_argument("--replace", action="store_true")
    push.add_argument("--dry-run", action="store_true")
    push.add_argument("--timeout", type=float, default=20.0)
    push.add_argument("--impersonate", default="chrome145")
    push.set_defaults(func=command_push)

    invite = subparsers.add_parser("invite", help="send a Team invite")
    invite.add_argument("--auth-json", required=True)
    invite.add_argument("--email", required=True)
    invite.add_argument("--account-id")
    _add_live_options(invite)
    invite.set_defaults(func=command_invite)

    leave = subparsers.add_parser("leave", help="delete a Team member (self-leave when user id is self)")
    leave.add_argument("--auth-json", required=True)
    leave.add_argument("--account-id")
    leave.add_argument("--user-id")
    _add_live_options(leave)
    leave.set_defaults(func=command_leave)

    create_token = subparsers.add_parser("create-token", help="create a Codex personal access token")
    create_token.add_argument("--auth-json", required=True)
    create_token.add_argument("--account-id")
    create_token.add_argument("--name")
    create_token.add_argument("--ttl", type=int, default=5_184_000)
    create_token.add_argument("--output")
    create_token.add_argument("--update-cpa")
    _add_live_options(create_token)
    create_token.set_defaults(func=command_create_token)

    refresh = subparsers.add_parser("refresh-session", help="exchange a session token for a fresh session JSON")
    refresh.add_argument("--auth-json", required=True)
    refresh.add_argument("--account-id")
    refresh.add_argument("--output", required=True)
    _add_live_options(refresh)
    refresh.set_defaults(func=command_refresh_session)

    web = subparsers.add_parser("web", help="open the local SQLite workflow console")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--no-browser", action="store_true")
    web.set_defaults(func=command_web)

    gui = subparsers.add_parser("gui", help="compatibility alias for the local web console")
    gui.add_argument("--port", type=int, default=8765)
    gui.add_argument("--no-browser", action="store_true")
    gui.set_defaults(func=command_gui)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
