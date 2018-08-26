
import asyncio
import json
import os
import logging
from base64 import b64decode, b64encode, urlsafe_b64encode
from hashlib import blake2b
from typing import cast, IO, Any

import click
from hbmqtt.client import QOS_1, MQTTClient

# Magic Constants
STATUS_ONLINE = b'online'
STATUS_OFFLINE = b'offline'
STATUS_RELOAD_CONFIG = b'reload_config'
STATUS_NEED_CONFIG = b'need_config'


def hmac(key: bytes, salt: bytes, data: bytes) -> bytes:
    'Perform an hmac using global key'
    h = blake2b(data,  # pylint: disable=unexpected-keyword-arg
                key=key,
                salt=salt)
    return b64encode(h.digest())


class Settings:
    DEFAULT_CONFIG = {
        'client': {
            'HMAC_KEY': None,
            'CLIENT_MQTT_URL':  None,
            'NODE_NAME': None,
            'CONFIG_TOPIC': 'config/{node}',
            'STATUS_TOPIC': 'status/{node}',
            'users': {},
        },
        'server':  {
            'log_level': 'warning',
            'security': {},
        }
    }

    def __init__(self, config_file: str) -> None:
        if (os.path.isfile(config_file)
                or config_file == '-'):
            with click.open_file(config_file) as f:
                self.data = json.load(cast(IO[Any], f))
        else:
            self.data = self.DEFAULT_CONFIG
        self.batch = False
        self.config_file = config_file

    def flush(self) -> None:
        f = click.open_file(self.config_file, mode='w',
                            atomic=True, lazy=True)
        try:
            json.dump(self.data, cast(IO[Any], f), indent=2)
            cast(IO[Any], f).close()
        finally:
            pass

    def is_initialized(self) -> bool:
        return self.data['client']['HMAC_KEY'] is not None


@click.group()
@click.option("--batch", is_flag=True)
@click.option("--config-file", envvar="CONFIG_FILE", default=".config.json",
              type=click.Path(dir_okay=False))
@click.option("-d", "--debug", is_flag=True)
@click.pass_context
def cli(ctx: click.Context, batch: bool,
        config_file: str, debug: bool) -> None:
    ctx.obj = Settings(config_file)
    ctx.obj.batch = batch
    if batch:
        ctx.resilient_parsing = True
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)


@cli.group()
def config():
    pass


@config.command()
@click.option("--client-mqtt-url", prompt=True,
              envvar="CLIENT_MQTT_URL", required=True)
@click.option("--node-name", envvar="NODE_NAME", default='p2hamb')
@click.option("--force", is_flag=True)
@click.pass_obj
def initialize(obj: Settings, client_mqtt_url: str,
               node_name: str, force: bool) -> None:
    if obj.is_initialized() and not force:
        click.echo("Error: Configuration already intialized", err=True)
        exit(1)
    obj.data['client']['CLIENT_MQTT_URL'] = client_mqtt_url
    obj.data['client']['NODE_NAME'] = node_name
    obj.data['client']['HMAC_KEY'] = b64encode(os.urandom(64)).decode()
    obj.flush()
    if obj.batch:
        click.echo(obj.data['client']['HMAC_KEY'])
    else:
        click.echo("Initialized")
        click.echo("HMAC_KEY=" +
                   click.style(b64encode(os.urandom(64)).decode(), fg='red'))


@config.command()
@click.pass_obj
@click.argument("username", required=False)
@click.option("--force", is_flag=True)
def create_user(obj: Settings, username: str, force: bool) -> None:
    'Cli command to create a new user and generate a new password and hash'
    if not obj.is_initialized():
        click.echo("Error: Configuration not initialized", err=True)
        exit(1)

    if username is None:
        try:
            username = click.prompt("Username")
        except click.Abort:
            exit(1)
    if (not force and (username in obj.data['server']['security']
                       or username in obj.data['client']['users'])):
        click.echo("Error: User already exists: " + username, err=True)
        exit(1)
    password = urlsafe_b64encode(os.urandom(64)).rstrip(b"=")
    salt = os.urandom(16)
    key = b64decode(obj.data['client']['HMAC_KEY'])
    h_password = hmac(key, salt, password).decode()
    password_str = password.decode()

    if username not in obj.data['server']['security']:
        obj.data['server']['security'][username] = {
            'salt': None,
            'password_hash': None,
            'whitelist': []
        }
    if username not in obj.data['client']['users']:
        obj.data['client']['users'][username] = {
            'password': None,
        }
    obj.data['server']['security'][username]['salt'] = b64encode(salt).decode()
    obj.data['server']['security'][username]['password_hash'] = h_password
    obj.data['client']['users'][username]['password'] = password_str

    obj.flush()
    if obj.batch:
        click.echo(password_str)
    else:
        click.echo("User created: " + username)
        click.echo("Password: " + click.style(password_str, fg='red'))
        click.echo("password_hash: " + click.style(h_password, fg='green'))


@cli.command()
@click.pass_obj
def push_config(obj: Settings) -> None:
    'Utility command to push a new configuration to the MQTT server'
    data = json.dumps(obj.data['server']).encode('UTF8')
    key = b64decode(obj.data['client']['HMAC_KEY'])
    signature = hmac(key, b'', data)
    config = data+signature
    click.echo("Pushing config:")
    click.echo(data)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_push_config(obj, config))
    loop.close()

    click.echo("Config published")


async def _push_config(obj: Settings, config: bytes) -> None:
    'Asyncrouns part of pushing a new configuration to the server'
    client_config = {
        'auto_reconnect': True,
        'ping_delay': 25,
        'keep_alive': 30,

    }
    client = MQTTClient(config=client_config)
    node_name = obj.data['client']['NODE_NAME']
    status_topic = obj.data['client']['STATUS_TOPIC'].replace(
        "{node}", node_name)
    config_topic = obj.data['client']['CONFIG_TOPIC'].replace(
        "{node}", node_name)
    click.echo("Connecting to %s..." % obj.data['client']['CLIENT_MQTT_URL'])
    await client.connect(obj.data['client']['CLIENT_MQTT_URL'])
    await client.subscribe([(status_topic, QOS_1)])
    click.echo("Publishing at %s ..." % config_topic)
    await client.publish(config_topic, config,
                         qos=QOS_1, retain=True)
    click.echo("Waiting on %s ..." % status_topic)
    while True:
        # wait for confirmation
        message = await client.deliver_message()
        if (message.topic == status_topic
                and message.data == STATUS_RELOAD_CONFIG):
            click.echo("Received confirmation of new configuration")
            break
        else:
            click.echo("Status: " + message.topic)
    await client.disconnect()

if __name__ == '__main__':
    cli()  # pylint: disable=no-value-for-parameter
