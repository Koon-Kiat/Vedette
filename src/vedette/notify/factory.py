"""Builds the configured delivery channel from settings."""

from vedette.config import Settings
from vedette.notify.channels import Channel, DiscordChannel, EmailChannel, NtfyChannel


def build_channel(settings: Settings) -> Channel | None:
    """The channel ``notify.channel`` names, or ``None`` when it is ``none``.

    Settings validation has already checked that the channel's secrets are set.
    """
    notify = settings.notify
    if notify.channel == "ntfy" and settings.ntfy_topic is not None:
        token = settings.ntfy_token.get_secret_value() if settings.ntfy_token else None
        return NtfyChannel(notify.ntfy.url, settings.ntfy_topic.get_secret_value(), token=token)
    if notify.channel == "discord" and settings.discord_webhook_url is not None:
        return DiscordChannel(settings.discord_webhook_url.get_secret_value())
    if notify.channel == "email":
        email = notify.email
        password = settings.smtp_password.get_secret_value() if settings.smtp_password else None
        return EmailChannel(
            host=email.host,
            port=email.port,
            security=email.security,
            username=email.username,
            password=password,
            sender=email.sender,
            recipients=email.recipients,
        )
    return None
