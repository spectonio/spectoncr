#!/usr/bin/env python3
"""Upload a PDF to Slack using the files.getUploadURLExternal flow.

Webhook URLs (incoming-webhooks) cannot attach files — only bot tokens can.
This script expects:

  SLACK_BOT_TOKEN   xoxb-… with files:write scope
  SLACK_CHANNEL_ID  e.g. C0123456789 (channel ID, not name)

Optional bot scopes:
  channels:join     lets the script auto-join a public channel on
                    `not_in_channel`. Private channels still need a
                    manual `/invite @yourapp` from the channel.

Optional:
  SLACK_WEBHOOK_URL fallback — used when SLACK_BOT_TOKEN is missing OR
                    when the bot-token upload fails (e.g. bot not in
                    channel and auto-join refused). Posts a plain text
                    notice so the channel still hears about the run.
                    (Webhooks can't carry the PDF itself.)

Exit codes:
  0  uploaded, intentionally skipped, OR notify-path soft-failed but the
     scan run itself is fine (PDF is in workflow artifacts)
  1  unexpected error in the upload path with no webhook fallback wired
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


SLACK_API = "https://slack.com/api"


def _http(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _slack_get(path: str, token: str, params: dict[str, str]) -> dict:
    q = urllib.parse.urlencode(params)
    code, body = _http(
        "GET",
        f"{SLACK_API}/{path}?{q}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"http_{code}", "raw": body.decode("replace")}


def _slack_post(path: str, token: str, payload: dict) -> dict:
    code, body = _http(
        "POST",
        f"{SLACK_API}/{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        data=json.dumps(payload).encode(),
    )
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"http_{code}", "raw": body.decode("replace")}


def _webhook_fallback(url: str, text: str) -> int:
    code, body = _http(
        "POST",
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps({"text": text}).encode(),
    )
    if 200 <= code < 300:
        print("webhook fallback posted")
        return 0
    print(f"webhook post failed: http {code}: {body!r}", file=sys.stderr)
    return 0  # don't fail the job on notify-path errors


def _join_channel(token: str, channel: str) -> dict:
    return _slack_post("conversations.join", token, {"channel": channel})


def _complete_upload(
    token: str, channel: str, file_id: str, title: str, initial_comment: str
) -> dict:
    return _slack_post(
        "files.completeUploadExternal",
        token,
        {
            "files": [{"id": file_id, "title": title}],
            "channel_id": channel,
            "initial_comment": initial_comment,
        },
    )


def _upload(token: str, channel: str, pdf_path: str) -> int:
    filename = os.path.basename(pdf_path)
    size = os.path.getsize(pdf_path)

    step1 = _slack_get(
        "files.getUploadURLExternal",
        token,
        {"filename": filename, "length": str(size)},
    )
    if not step1.get("ok"):
        print(f"getUploadURLExternal failed: {step1}", file=sys.stderr)
        return 1

    upload_url = step1["upload_url"]
    file_id = step1["file_id"]

    with open(pdf_path, "rb") as fh:
        pdf_bytes = fh.read()
    code, body = _http(
        "POST",
        upload_url,
        headers={"Content-Type": "application/pdf"},
        data=pdf_bytes,
    )
    if not (200 <= code < 300):
        print(f"PDF PUT failed: http {code}: {body!r}", file=sys.stderr)
        return 1

    title = os.environ.get("SLACK_TITLE") or "SpectonCR nightly CVE scan"
    initial_comment = (
        os.environ.get("SLACK_INITIAL_COMMENT")
        or f":shield: {title} — PDF report attached."
    )
    step3 = _complete_upload(token, channel, file_id, title, initial_comment)

    # Self-heal for public channels: Slack returns `not_in_channel` when the
    # bot hasn't been added to the destination. `conversations.join` (scope
    # `channels:join`) lets us add ourselves to public channels without a
    # human running `/invite`. Private channels reject `conversations.join`
    # with `method_not_supported_for_channel_type` — those still need a
    # manual invite, which we surface clearly below.
    if not step3.get("ok") and step3.get("error") == "not_in_channel":
        print(
            f"bot is not in channel {channel} — attempting conversations.join",
            file=sys.stderr,
        )
        joined = _join_channel(token, channel)
        if joined.get("ok"):
            print(f"joined channel {channel}; retrying upload", file=sys.stderr)
            step3 = _complete_upload(token, channel, file_id, title, initial_comment)
        else:
            print(f"conversations.join failed: {joined}", file=sys.stderr)
            print(
                "hint: if this is a private channel, run "
                "`/invite @<your-bot-name>` in that channel; "
                "if public, ensure the bot has the `channels:join` scope.",
                file=sys.stderr,
            )

    if not step3.get("ok"):
        print(f"completeUploadExternal failed: {step3}", file=sys.stderr)
        return 1

    print(f"uploaded {filename} ({size} bytes) to channel {channel}")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: slack-upload-pdf.py <path/to.pdf>", file=sys.stderr)
        return 2
    pdf_path = sys.argv[1]

    if not os.path.isfile(pdf_path):
        print(f"no PDF at {pdf_path} — skipping Slack upload")
        return 0

    token = os.environ.get("SLACK_BOT_TOKEN") or ""
    channel = os.environ.get("SLACK_CHANNEL_ID") or ""
    webhook = os.environ.get("SLACK_WEBHOOK_URL") or ""

    if token and channel:
        rc = _upload(token, channel, pdf_path)
        if rc == 0:
            return 0
        # Bot-token path failed (e.g. bot not in channel and auto-join refused).
        # The PDF is still in the workflow artifact — fall back to the webhook
        # so the channel hears about the run instead of failing the step.
        if webhook:
            print(
                "bot-token upload failed — falling back to webhook text post",
                file=sys.stderr,
            )
            return _webhook_fallback(
                webhook,
                ":shield: SpectonCR nightly CVE scan finished, but the bot "
                "could not attach the PDF to this channel "
                "(see workflow logs for the Slack API error). "
                "Report is in the workflow artifacts.",
            )
        return rc

    if webhook:
        print(
            "SLACK_BOT_TOKEN/SLACK_CHANNEL_ID not set — "
            "posting text notice via webhook instead (no PDF attached).",
            file=sys.stderr,
        )
        return _webhook_fallback(
            webhook,
            ":shield: SpectonCR nightly CVE scan finished. "
            "PDF report is in the workflow artifacts "
            "(set SLACK_BOT_TOKEN + SLACK_CHANNEL_ID to get it attached here).",
        )

    print(
        "no Slack credentials configured — skipping notification",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
