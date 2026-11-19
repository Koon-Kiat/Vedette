import pytest

from sentinel.config import load_settings
from sentinel.notify.channels import Channel, DiscordChannel, EmailChannel, NtfyChannel
from sentinel.notify.factory import build_channel

WEBHOOK = "https://discord.com/api/webhooks/123456789/not-a-real-token_value"


def test_no_channel_is_built_when_none_is_configured() -> None:
    assert build_channel(load_settings()) is None


@pytest.mark.parametrize(
    ("name", "kind"),
    [("ntfy", NtfyChannel), ("discord", DiscordChannel), ("email", EmailChannel)],
)
async def test_each_configured_channel_is_built(
    monkeypatch: pytest.MonkeyPatch, name: str, kind: type[Channel]
) -> None:
    monkeypatch.setenv("NTFY_TOPIC", "topic")
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", WEBHOOK)
    monkeypatch.setenv("SENTINEL_NOTIFY__EMAIL__HOST", "smtp.example.org")
    monkeypatch.setenv("SENTINEL_NOTIFY__EMAIL__SENDER", "me@example.org")
    monkeypatch.setenv("SENTINEL_NOTIFY__EMAIL__RECIPIENTS", '["me@example.org"]')
    monkeypatch.setenv("SENTINEL_NOTIFY__CHANNEL", name)

    channel = build_channel(load_settings())

    assert isinstance(channel, kind)
    await channel.aclose()
