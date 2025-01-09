import json

from discord_webhook import DiscordWebhook, DiscordEmbed

WEBHOOK_URL = ""

with open("config.json", "r") as f:
    config = json.load(f)
    WEBHOOK_URL = config["WEBHOOK_URL"]

def send_webhook(title, content, sender):
    webhook = DiscordWebhook(url=WEBHOOK_URL)
    embed = DiscordEmbed(
        title=title,
        description=content
    )
    embed.set_author(sender)
    embed.color = 0xAAAAFF

    webhook.add_embed(embed)
    webhook.execute()