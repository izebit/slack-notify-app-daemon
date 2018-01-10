# Slack notify daemon  
:rocket:

### What is it for?  
It is a daemon for notification slack users about errors, which has contained on elastic search server.


### How can you run this app?  
There are only two steps:  
- you should have python with version 3 on your computer
- execute below the command:

```bash
python notify-slack-app.py --elastic-search-domain=<elastic_search_address> \
                           --slack-channel=<channel_which_app_notices_to>  \
                           --slack-channel-web-hook-url=<web_hooks_for_slack_app> \
                           --slack-bot-token=<access_token_for_slack_boot>;
```
