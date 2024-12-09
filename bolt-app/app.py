import os
import logging
import ip_helpers
import time
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
# TODO Add ability to use HTTP instead of socket mode

# Initializes your app with your bot token and socket mode handler
app = App(token=os.environ.get("SLACK_BOT_TOKEN"))

@app.message()
def parse_message(logger, message, say):
    logger.info(message)
    ips = ip_helpers.parse_for_ip(message['text'])
    ip_count = len(ips)
    if ip_count == 0:
        logger.info("No IP addresses found in the message")
    else:
        # parsed_vt_data = []
        if ip_count == 1:
            say(f"{ip_count} IP Address was found in the message")
        else
            say(f"{ip_count} IP Addresses were found in the message")
            say(blocks=[{"type": "divider"}])
            for ip in ips:
                logger.info(f"IP address found: {ip}")
                vt_data = ip_helpers.enrich_virustotal(logger, ip)
                parsed_vt_data = ip_helpers.parse_vt_data(vt_data)
                say(blocks=[ip_helpers.build_block_response(ip, parsed_vt_data)])
                say(blocks=[{"type": "divider"}])

@app.action("button-action")
def button_action(ack):
    ack()

# Start your app
if __name__ == "__main__":
    SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"]).start()