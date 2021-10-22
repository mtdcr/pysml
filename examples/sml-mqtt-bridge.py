#!/usr/bin/env python3
#
# Copyright 2020 Andreas Oberritter
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import argparse
import asyncio
import json
import logging
import signal
import ssl
import sys
from functools import partial
from typing import Callable, Union
from urllib.parse import urlparse

from asyncio_mqtt import Client, MqttError, Will
from sml import SmlSequence, SmlGetListResponse
from sml.asyncio import SmlProtocol
from slugify import slugify

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())


class WatchdogTimer:
    def __init__(self, timeout):
        self._wdt_reset = asyncio.Event()
        self._wdt_status = None
        self._wdt_task = None
        self._wdt_timeout = timeout

    async def _watchdog(self, callback) -> None:
        while True:
            logger.debug("Watchdog: Waiting for data")

            self._wdt_reset.clear()
            try:
                await asyncio.wait_for(
                    self._wdt_reset.wait(), self._wdt_timeout
                )
            except asyncio.TimeoutError:
                status = False
            else:
                status = True

            if not status:
                logger.warning("Watchdog: Timeout")

            if self._wdt_status != status:
                self._wdt_status = status
                await callback(status)

    def start(self, callback: Callable[[bool], None]) -> None:
        logger.debug("Watchdog: Starting")
        self._wdt_task = asyncio.create_task(self._watchdog(callback))

    def stop(self) -> None:
        logger.debug("Watchdog: Stopping")
        self._wdt_task.cancel()

    def reset(self) -> None:
        logger.debug("Watchdog: Reset")
        self._wdt_reset.set()

    async def wait_reset(self) -> None:
        logger.debug("Watchdog: Waiting for reset")
        await self._wdt_reset.wait()


class MqttBridge:
    def __init__(self, cfg: dict):
        self._callbacks = {}
        self._cfg = cfg
        self._mainloop_task = None
        self._mqtt_cache = {}
        self._hass_birth_topic = cfg.get("hass_birth_topic")
        self._hass_birth_payload = cfg.get("hass_birth_payload")

    async def _hass_birth(self, data: str):
        if data == self._hass_birth_payload:
            self._mqtt_cache = {}

    async def _process_packet(self, message) -> None:
        callbacks = self._callbacks.get(message.topic)
        if not callbacks:
            logger.error("Unhandled topic: %s", message.topic)
            return

        try:
            data = message.payload.decode("utf-8")
        except UnicodeDecodeError:
            logger.error("Invalid payload: %s", message.payload)
        else:
            for callback in callbacks:
                if not await callback(data):
                    logger.error("Invalid parameter: %s", data)

    async def _publish(
        self,
        mqtt,
        topic: str,
        message: Union[bool, bytes, dict, float, int, str],
        retain: bool = False,
    ) -> None:
        if isinstance(message, dict):
            message = json.dumps(message)
        elif isinstance(message, bool):
            message = [b"OFF", b"ON"][message]
        elif isinstance(message, (float, int)):
            message = str(message)

        if isinstance(message, str):
            message = message.encode("utf-8")

        assert isinstance(message, bytes)

        if self._mqtt_cache.get(topic) == message:
            return
        self._mqtt_cache[topic] = message

        logger.debug(f"Publish: {topic} {message}")
        await mqtt.publish(topic, message, qos=2, retain=retain)

    async def _subscribe(
        self, mqtt, topic: str, callback: Callable[[str], None]
    ) -> None:
        if topic not in self._callbacks:
            self._callbacks[topic] = set()
        self._callbacks[topic].add(callback)
        await mqtt.subscribe(topic)

    async def _subscribe_hass_birth(self, mqtt) -> None:
        if self._hass_birth_topic and self._hass_birth_payload:
            await self._subscribe(
                mqtt, self._hass_birth_topic, self._hass_birth
            )

    async def _unsubscribe(
        self, mqtt, topic: str, callback: Callable[[str], None]
    ) -> None:
        self._callbacks[topic].remove(callback)
        if not self._callbacks[topic]:
            del self._callbacks[topic]
        await mqtt.unsubscribe(topic)

    async def _unsubscribe_hass_birth(self, mqtt) -> None:
        if self._hass_birth_topic and self._hass_birth_payload:
            await self._unsubscribe(
                mqtt, self._hass_birth_topic, self._hass_birth
            )

    async def _mainloop(self, messages) -> None:
        logger.debug("Running mainloop")
        async for message in messages:
            await self._process_packet(message)

    def _cancel_mainloop(self) -> None:
        loop = asyncio.get_running_loop()
        loop.remove_signal_handler(signal.SIGTERM)
        self._mainloop_task.cancel()

    async def _run_mainloop(self, mqtt) -> None:
        await self._subscribe_hass_birth(mqtt)

        async with mqtt.unfiltered_messages() as messages:
            self._mainloop_task = asyncio.create_task(self._mainloop(messages))

            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGTERM, self._cancel_mainloop)
            try:
                await self._mainloop_task
            except asyncio.CancelledError:
                pass

        await self._unsubscribe_hass_birth(mqtt)


class SmlMqttBridge(MqttBridge):
    HASS_SENSORS = {
        # A=1: Electricity
        # C=0: General purpose objects
        "1-0:0.0.9*255": "Electricity ID",
        # C=1: Active power +
        # D=8: Time integral 1
        # E=0: Total
        "1-0:1.8.0*255": "Positive active energy total",
        # E=1: Rate 1
        "1-0:1.8.1*255": "Positive active energy in tariff T1",
        # E=2: Rate 2
        "1-0:1.8.2*255": "Positive active energy in tariff T2",
        # D=17: Time integral 7
        # E=0: Total
        "1-0:1.17.0*255": "Last signed positive active energy total",
        # C=2: Active power -
        # D=8: Time integral 1
        # E=0: Total
        "1-0:2.8.0*255": "Negative active energy total",
        # E=1: Rate 1
        "1-0:2.8.1*255": "Negative active energy in tariff T1",
        # E=2: Rate 2
        "1-0:2.8.2*255": "Negative active energy in tariff T2",
        # C=15: Active power absolute
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:15.7.0*255": "Absolute active instantaneous power",
        # C=16: Active power sum
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:16.7.0*255": "Sum active instantaneous power",
        # C=31: Active amperage L1
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:31.7.0*255": "L1 active instantaneous amperage",
        # C=36: Active power L1
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:36.7.0*255": "L1 active instantaneous power",
        # C=51: Active amperage L2
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:51.7.0*255": "L2 active instantaneous amperage",
        # C=56: Active power L2
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:56.7.0*255": "L2 active instantaneous power",
        # C=71: Active amperage L3
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:71.7.0*255": "L3 active instantaneous amperage",
        # C=76: Active power L3
        # D=7: Instantaneous value
        # E=0: Total
        "1-0:76.7.0*255": "L3 active instantaneous power",
        # C=96: Electricity-related service entries
        "1-0:96.1.0*255": "Metering point ID 1",
    }

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self._cache = {}
        self._cfg = cfg
        self._name = "SML"
        self._proto = SmlProtocol(cfg["port"])
        self._wdt = WatchdogTimer(cfg["watchdog_timeout"])

    async def _device_id(self) -> str:
        if not self._cache:
            await self._wdt.wait_reset()

        # Serial number or public key
        for obis in (
            "1-0:0.0.9*255",
            "1-0:96.1.0*255",
            "129-129:199.130.5*255",
        ):
            value = self._cache.get(obis, {}).get("value")
            if value:
                return value

        assert False, "No device ID found"

    async def _base_topic(self, name):
        device_id = await self._device_id()
        return f"{self._name}/{slugify(device_id)}/{slugify(name)}"

    async def _obis_topic(self, objName, attribute):
        return await self._base_topic(objName) + f"/{attribute}"

    def _hass_topic(self, component: str, object_id: str) -> str:
        object_id = slugify(object_id)
        return f"homeassistant/{component}/sml/{object_id}/config"

    def _event(self, mqtt, message_body: SmlSequence) -> None:
        assert isinstance(message_body, SmlGetListResponse)

        for val in message_body.get("valList", []):
            name = val.get("objName")
            if name:
                logger.debug("OBIS: %s", val)
                self._cache[name] = val
                if mqtt:
                    asyncio.create_task(self._publish_obis(mqtt, val))

        self._wdt.reset()

    async def _publish_obis(self, mqtt, obj):
        name = obj["objName"]
        for k, v in obj.items():
            topic = await self._obis_topic(name, k)
            await self._publish(mqtt, topic, v)

    async def _publish_availability(self, mqtt, status: bool) -> None:
        await self._publish(
            mqtt,
            await self._base_topic("availability"),
            [b"offline", b"online"][status],
            retain=True,
        )

    async def _publish_hass_config(self, mqtt) -> None:
        device_id = await self._device_id()
        availability_topic = await self._base_topic("availability")

        device = {"name": self._name, "identifiers": [device_id]}
        obj = self._cache.get("129-129:199.130.3*255")
        if obj and "value" in obj:
            device["manufacturer"] = obj["value"]
        else:
            parts = device_id.split()
            if len(parts) == 4 and len(parts[1] == 3):
                device["manufacturer"] = parts[1]

        # https://www.home-assistant.io/integrations/sensor.mqtt/
        prefix = self._cfg["hass_name"]
        for obis, name in self.HASS_SENSORS.items():
            obj = self._cache.get(obis)
            if not obj:
                continue

            object_id = f"{device_id}-{obis}"
            config = {
                "availability_topic": availability_topic,
                "device": device,
                "name": prefix and f"{prefix} {name}" or name,
                "state_topic": await self._obis_topic(obis, "value"),
                "unique_id": object_id,
            }
            unit = obj.get("unit")
            if unit:
                config["unit_of_measurement"] = unit
                if unit == "W":
                    config["device_class"] = "power"
                    config["state_class"] = "measurement"
                elif unit == "Wh":
                    config["device_class"] = "energy"
                    config["last_reset_topic"] = config["state_topic"]
                    config["last_reset_value_template"] = "1970-01-01T00:00:00+00:00"
                    config["state_class"] = "total_increasing"

            topic = self._hass_topic("sensor", object_id)
            await self._publish(mqtt, topic, config, retain=True)

    async def run(self) -> None:
        event = partial(self._event, None)
        self._proto.add_listener(event, ["SmlGetListResponse"])
        await self._proto.connect()

        p = urlparse(self._cfg["broker"], scheme="mqtt")
        if p.scheme not in ("mqtt", "mqtts") or not p.hostname:
            raise ValueError

        tls_context = None
        if p.scheme == "mqtts":
            tls_context = ssl.create_default_context()

        will = Will(
            await self._base_topic("availability"),
            payload=b"offline",
            qos=2,
            retain=True,
        )

        self._proto.remove_listener(event, ["SmlGetListResponse"])

        async with Client(
            p.hostname,
            port=p.port or p.scheme == "mqtt" and 1883 or 8883,
            username=p.username,
            password=p.password,
            logger=logger,
            tls_context=tls_context,
            will=will,
        ) as mqtt:
            watchdog_callback = partial(self._publish_availability, mqtt)
            self._wdt.start(watchdog_callback)

            event = partial(self._event, mqtt)
            self._proto.add_listener(event, ["SmlGetListResponse"])

            if self._cfg["hass"]:
                await self._publish_hass_config(mqtt)

            await self._run_mainloop(mqtt)

            self._proto.remove_listener(event, ["SmlGetListResponse"])

            self._wdt.stop()
            await self._publish_availability(mqtt, False)


async def main(cfg: dict) -> None:
    if cfg["debug"]:
        logger.setLevel(logging.DEBUG)
    try:
        await SmlMqttBridge(cfg).run()
    except MqttError as exc:
        logger.critical(exc)
        sys.exit(1)


def options() -> dict:
    cfg = {
        "config": "/var/lib/sml-mqtt-bridge/config.json",
        "broker": "mqtt://localhost",
        "port": "/dev/ttyUSB0",
        "hass_name": None,
        "hass_birth_topic": "homeassistant/status",
        "hass_birth_payload": "online",
        "watchdog_timeout": 10,
    }

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config", help=f"Location of config file (default: {cfg['config']})"
    )
    parser.add_argument(
        "--broker", help=f"MQTT broker (default: {cfg['broker']})"
    )
    parser.add_argument("--port", help=f"Serial port (default: {cfg['port']})")
    parser.add_argument(
        "--hass",
        action="store_true",
        help="Publish discovery information for Home Assistant",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable logging of debug messages"
    )
    parser.add_argument(
        "--hass-name", help="Prefix for entitiy IDs in Home Assistant"
    )
    parser.add_argument(
        "--hass-birth-topic",
        help=f"MQTT Birth topic of Home Assistant (default: {cfg['hass_birth_topic']})",
    )
    parser.add_argument(
        "--hass-birth-payload",
        help=f"MQTT Birth payload of Home Assistant (default: {cfg['hass_birth_payload']})",
    )
    parser.add_argument(
        "--watchdog-timeout", help=f"(default: {cfg['watchdog_timeout']})"
    )

    args = parser.parse_args()
    filename = args.config or cfg["config"]

    try:
        with open(filename, "r") as f:
            cfg.update(json.load(f))
    except OSError as exc:
        if args.config or not isinstance(exc, FileNotFoundError):
            logger.error("Failed to open configuration file: %s", exc)
            sys.exit(1)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse configuration file: %s", exc)
        sys.exit(1)

    for key, value in vars(args).items():
        if value is not None:
            cfg[key] = value

    return cfg


try:
    asyncio.run(main(options()))
except KeyboardInterrupt:
    pass
