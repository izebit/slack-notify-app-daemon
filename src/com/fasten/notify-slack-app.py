#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import time
import urllib.parse
import urllib.request
from urllib.parse import urlencode
from urllib.request import Request, urlopen

__author__ = 'Artem Konovalov <a.konovalov@fasten.com>'
__version__ = '1.0'

SEVERITY_LIST = ['error']
DUPLICATE_THRESHOLD = 10


class SlackSender:
    _bot_token = None
    _channel_name = None
    _channel_web_hook_url = None

    def __init__(self, bot_token, channel_web_hook_url, channel_name):
        self._bot_token = bot_token
        self._channel_name = channel_name
        self._channel_web_hook_url = channel_web_hook_url

    def _send_msg(self, title, text, pretext, color):
        url = 'https://hooks.slack.com/services/' + self._channel_web_hook_url
        data = {
            "attachments": [
                {
                    "title": title,
                    "color": color,
                    "pretext": pretext,
                    "text": text
                }
            ]
        }
        request_body = json.dumps(data).encode('utf-8')
        headers = {
            'Content-Type': 'application/json',
            'Content-Length': len(request_body)
        }

        request = Request(url, request_body, headers)
        urlopen(request).read().decode()

    def send_info(self, text):
        self._send_msg("Hi", text, "", 'good')

    def send_error(self, text):
        self._send_msg("Error:", text, "There is something wrong with me", 'danger')

    def send_data(self, items):
        if len(items) == 0:
            return

        print(">> sending data")

        for app_name, logs in items.items():
            print(app_name)
            for log in logs:
                url = 'https://slack.com/api/files.upload'
                request_params = {
                    'channels': self._channel_name,
                    'token': self._bot_token,
                    'filetype': 'java',
                    'title': "{}-{}".format(log.application, log.severity),
                    'filename': '{}.log'.format(app_name),
                    'content': '{}\n{}'.format(log.message, log.stacktrace),
                    'initial_comment': 'application: {} \n date: {}'.format(log.application,
                                                                            log.date.strftime("%Y-%m-%d %H:%M"))
                }

                request = Request(url, urlencode(request_params).encode())
                response = urlopen(request).read().decode()
                print(response)


class Log:
    severity = None
    application = None
    message = None
    stacktrace = None
    date = None

    def __init__(self, application, severity, message, stacktrace, timestamp):
        self.application = application
        self.severity = severity
        self.message = message
        self.stacktrace = '' if stacktrace is None else stacktrace
        self.date = Log._parse_timestamp(timestamp)

    @staticmethod
    def _parse_timestamp(dt_str):
        dt, _, us = dt_str.partition(".")
        dt = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
        us = int(us.rstrip("Z"), 10)
        return dt + datetime.timedelta(microseconds=us)

    @staticmethod
    def remove_duplicates(items):
        tmp_set = set(items)
        for i in range(0, len(items)):
            for j in range(i + 1, len(items)):

                count = Log._get_max_common_substring_len(items[i].message, items[j].message)
                if count > DUPLICATE_THRESHOLD:
                    if items[j] in tmp_set:
                        tmp_set.remove(items[j])

        items.clear()
        items.extend(tmp_set)

    @staticmethod
    def _get_max_common_substring_len(s1, s2):
        if s1 is None or s2 is None:
            return 0

        min_len = min(len(s1), len(s2))
        result = 0
        count = 0
        for index in range(0, min_len):
            if s1[index] == s2[index]:
                count += 1
            else:
                result = max(result, count)
                count = 0

        return max(result, count)


class ElasticSearchLoader:
    _server_url = None
    _last_update_time = None

    def __init__(self, server_url):
        self._last_update_time = datetime.datetime.today()
        self._server_url = server_url

    def _load_json(self, limit=10):
        body = {
            "query": {
                "bool": {
                    "filter": {
                        "terms": {"severity": SEVERITY_LIST}
                    },
                    "must": {
                        "range": {
                            "@timestamp": {
                                "gt": self._last_update_time.strftime('%d/%m/%Y'),
                                "format": "dd/MM/yyyy"
                            }
                        }
                    }
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc"}}
            ],
            "from": 0, "size": limit,
            "_source": ["severity", "application", "message", "stacktrace", "@timestamp"]
        }
        request_body = json.dumps(body).encode('utf-8')

        headers = {
            'Content-Type': 'application/json',
            'Content-Length': len(request_body)
        }

        url = self._server_url + 'logs-*/_search'
        request = urllib.request.Request(url, 'GET', headers)
        response = urllib.request.urlopen(request, request_body, timeout=1000).read().decode('utf-8')
        return json.loads(response)['hits']['hits']

    @staticmethod
    def _parse(data):
        result = []

        for entry in data:
            information = entry['_source']
            application = information['application']
            severity = information['severity']
            message = information.get('message', '')
            stacktrace = information.get('stacktrace', '')
            timestamp = information['@timestamp']
            log = Log(application, severity, message, stacktrace, timestamp)
            result.append(log)

        return result

    def load(self):
        result = {}

        while True:
            data = self._load_json()
            if len(data) == 0:
                break

            logs = ElasticSearchLoader._parse(data)
            for log in logs:
                result.setdefault(log.application, [])
                result.get(log.application).append(log)
                self._last_update_time = max(log.date, self._last_update_time)

            for log_list in result.values():
                Log.remove_duplicates(log_list)

        return result


class Watcher:
    sender = None
    loader = None

    def __init__(self, consumer, producer):
        self.loader = producer
        self.sender = consumer

    def watcher(self):
        self.sender.send_info("i started work")

        while True:
            logs = {}
            try:
                logs = self.loader.load()
            except Exception as e:
                sender.send_error('error while loading logs from elastic search:{}'.format(e))

            try:
                sender.send_data(logs)
            except Exception as e:
                sender.send_error('error while sending notifies about errors: {}'.format(e))

            time.sleep(120)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='slack notify demon', prefix_chars='-+')
    parser.add_argument('--elastic-search-domain', required=True, help='domain of elastic search')
    parser.add_argument('--slack-channel', required=True, help='slack channels which daemon will sends notify to')
    parser.add_argument('--slack-channel-web-hook-url', required=True, help='access token to slack for channel')
    parser.add_argument('--slack-bot-token', required=True, help='access token to slack for bot')

    args = parser.parse_args()
    sender = SlackSender(args.slack_bot_token,
                         args.slack_channel_web_hook_url,
                         args.slack_channel)

    loader = ElasticSearchLoader(args.elastic_search_domain)

    watcher = Watcher(sender, loader)
    watcher.watcher()
