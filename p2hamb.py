import asyncio
import binascii
import json
import logging
import os
import re
from base64 import b64decode, b64encode
from hashlib import blake2b
from hmac import compare_digest
from typing import Any, Mapping, MutableMapping, Optional, cast

from hbmqtt.client import QOS_0, QOS_1, MQTTClient
from hbmqtt.mqtt.connack import ConnackPacket
from hbmqtt.plugins.manager import Plugin
from hbmqtt.session import ApplicationMessage
from quart import Quart, abort, request
from quart.exceptions import HTTPStatus, HTTPStatusException

# Magic Constants
STATUS_ONLINE = b'online'
STATUS_OFFLINE = b'offline'
STATUS_RELOAD_CONFIG = b'reload_config'
STATUS_NEED_CONFIG = b'need_config'

TOPIC_VALIDATION = re.compile("[a-zA-Z0-9/]+$")
USERNAME_VALIDATION = re.compile("[a-zA-Z0-9]+$")

# setup app and configuration items from environment
app = Quart(__name__)
app.config['MQTT_URL'] = os.environ['MQTT_URL']
app.config['HMAC_KEY'] = b64decode(os.environ['HMAC_KEY'])
app.config['NODE_NAME'] = os.environ['NODE_NAME']
app.config['CONFIG_TOPIC'] = (os.environ.get('CONFIG_TOPIC', 'config/{node}')
                                .replace('{node}', app.config['NODE_NAME']))
app.config['STATUS_TOPIC'] = (os.environ.get('CONFIG_TOPIC', 'status/{node}')
                                .replace('{node}', app.config['NODE_NAME']))
# dynamic configuration from mqtt
app.config['config'] = None

# global mqtt connection
mqtt: Optional[MQTTClient] = None


class Unauthorized(HTTPStatusException):
    '''Custom Unauthorized (401) HTTP Exception with www-authenticate header'''
    status = HTTPStatus.UNAUTHORIZED

    def __init__(self, www_authenticate: str) -> None:
        super().__init__()
        self.www_authenticate = www_authenticate

    def get_headers(self) -> dict:
        headers = super().get_headers()
        headers['WWW-Authenticate'] = self.www_authenticate
        return headers


class OnConnectPlugin:
    '''hbmqtt plugin to execute callback on connect'''

    def __init__(self, callback):
        self.callback = callback

    async def on_mqtt_packet_received(self, *args, **kwargs):
        packet = kwargs.get('packet')
        if isinstance(packet, ConnackPacket):
            asyncio.ensure_future(self.callback())

    def add_to_plugins(self, client):
        client.plugins_manager._plugins.append(
            Plugin(type(self).__name__,
                   None,
                   self)
        )


def assert_config() -> Mapping[str, Any]:
    'Assert that configuration is available and return. Else abort 500'
    config: Mapping = app.config['config']
    if config is None:
        app.logger.error("Config not available yet")
        abort(500)
    return config


async def handle_config(message: ApplicationMessage) -> None:
    'Authenticate and preprocess a new configuration from a message'
    data: bytes
    signature: bytes
    data, signature = message.data[:-88], message.data[-88:]

    signature_ = hmac(b'', data)
    if not compare_digest(signature, signature_):
        app.logger.error("Invalid config mac")
        return
    config: MutableMapping[str, Any] = json.loads(data)
    # convert filters to regex. Also allow node and user substitution
    user: str
    user_data: MutableMapping[str, Any]
    for user, user_data in config['security'].items():
        user_data['whitelist_re'] = [
            re.compile(topic.replace("{node}", os.environ['NODE_NAME'])
                            .replace("{user}", user)
                            .replace("+", '[^/]*')
                            .replace("/#", "(?:/.+)?$")
                       )
            for topic in user_data['whitelist']
        ]
    log_level = getattr(logging, config['log_level'].upper(), None)
    if not isinstance(log_level, int):
        app.logger.error("Invalid log level: %s" % config['log_level'])
    else:
        logging.basicConfig(level=log_level)

    app.config['config'] = config
    app.logger.info("Set new configuration")


async def handle_messages(client: MQTTClient) -> None:
    'Handle incoming messages'
    while True:
        try:
            message: ApplicationMessage = await client.deliver_message()
            app.logger.info("Received message on " + message.topic)
            if message.topic == app.config['CONFIG_TOPIC']:
                await handle_config(message)
                await client.publish(app.config['STATUS_TOPIC'],
                                     STATUS_RELOAD_CONFIG)
        except Exception as e:
            app.logger.error("Error in subscribtion. Retrying", exc_info=e)


async def connect_mqtt() -> MQTTClient:
    'Handle connection and setup of a MQTT Client'
    config = {
        'will': {
            # this topic is posted on disconnection
            'retain': True,
            'topic': app.config['STATUS_TOPIC'],
            'message': STATUS_OFFLINE,
            'qos': QOS_0

        },
        'ping_delay': 10,
        'keep_alive': 15,
        'auto_reconnect': True,
        'reconnect_max_interval': 5,
        'reconnect_retries': 10000,
        'default_qos': QOS_1,
    }
    client = MQTTClient(client_id=app.config['NODE_NAME'], config=config)
    await client.connect(app.config['MQTT_URL'], cleansession=False)

    # subscribe
    await client.subscribe([
        (app.config['CONFIG_TOPIC'], QOS_1)
    ])

    # Add plugin to publish birth on reconnect
    async def _publish_birth():
        await client.publish(app.config['STATUS_TOPIC'], STATUS_ONLINE,
                             retain=True)
    OnConnectPlugin(_publish_birth).add_to_plugins(client)
    # publish birth
    await client.publish(app.config['STATUS_TOPIC'], STATUS_ONLINE,
                         retain=True)

    # handle messages
    asyncio.ensure_future(handle_messages(client))
    return client


async def get_mqtt() -> MQTTClient:
    'Retreive global mqtt or create a new one'
    global mqtt
    if mqtt is None:
        mqtt = await connect_mqtt()
    return mqtt


def hmac(salt: bytes, data: bytes) -> bytes:
    'Perform an hmac using global key'
    key: bytes = app.config['HMAC_KEY']
    h = blake2b(data,  # pylint: disable=unexpected-keyword-arg
                salt=salt, key=key)
    return b64encode(h.digest())


@app.route("/<path:topic>/publish")
async def publish(topic: str):
    'Main Publishing route for mqtt'
    security: Mapping[str, Any] = assert_config()['security']
    user: Optional[str] = None
    password: Optional[str] = None
    # Perform Authentication with:
    #      Authorization header,
    #      query params,
    #      form encoded body,
    #      or json encoded body

    # Authorization Header
    if 'Authorization'in request.headers:
        auth_type: str
        data: str
        auth_type, _, data = request.headers['Authorization'].partition(' ')
        if auth_type.lower() != 'basic':
            app.logger.error("Authorization not basic")
            raise Unauthorized('basic')
        try:
            b_data: bytes = b64decode(data)
            data = b_data.decode('ascii')
        except (binascii.Error, UnicodeDecodeError):
            app.logger.error("Error decoding authorization header")
            raise Unauthorized('basic')
        user, _, password = data.partition(":")
    values = await request.values

    # query parameters or form-encoded body
    if user is None:
        user = values.get('user', None)
    if password is None:
        password = values.get('password', None)

    # Json-encoded body
    json = await request.get_json()
    if user is None and json is not None:
        user = json.get('user', None)
    if password is None and json is not None:
        password = json.get('password', None)

    # sanity check username
    if user is None:
        app.logger.error("User is not specified")
        raise Unauthorized('basic')
    user = cast(str, user)  # Discard Optional type

    if not USERNAME_VALIDATION.match(user):
        app.logger.error("Invalid user encoding")
        raise Unauthorized('basic')

    # sanity check password
    if password is None:
        app.logger.error("Password is not specified")
        raise Unauthorized('basic')
    password = cast(str, password)  # discard Optional type
    try:
        b_password = password.encode('ascii')
    except UnicodeError:
        app.logger.error("invalid password encoding")
        raise Unauthorized('basic')

    # authentication
    # hmac password before userlookup to mitigate timing attacks
    salt = b64decode(security[user]['salt'])
    h_password = hmac(salt, b_password)

    if user not in security:
        app.logger.error("User not found")
        raise Unauthorized('basic')

    h_password_ = security[user]['password_hash'].encode('ascii')
    if not compare_digest(h_password, h_password_):
        app.logger.error("Password does not verify")
        raise Unauthorized('basic')

    # sanity check topic
    if not TOPIC_VALIDATION.match(topic):
        app.logger.error("Invalid topic " + topic[:30])
        abort(404)

    # authorization by looking up whitelisted topics
    for r in security[user]['whitelist_re']:
        if r.match(topic):
            break
    else:
        app.logger.error("Topic not whitelisted: " + topic[:30])
        abort(403)

    # get message
    msg = values.get("msg", None)
    if msg is None and json is not None:
        msg = json.get("msg")
    if msg is None:
        msg = b""
    else:
        msg = msg.encode('utf8')

    client = await get_mqtt()
    message = await client.publish(topic, msg)

    return "Cool " + topic + " Published " + message.data.decode('ascii')


@app.route("/keep-alive")
async def keep_alive():
    return "Ping!"


@app.before_serving
async def start():
    '''Pre-connect mqtt client so first request is fast.
       It is possible this function may not be called'''
    await get_mqtt()

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=os.environ['PORT'])
