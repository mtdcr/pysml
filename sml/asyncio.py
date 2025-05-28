#
# Copyright (c) 2024 Andreas Oberritter
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

import asyncio
import logging
import time
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from serial import SerialException
from serial_asyncio_fast import create_serial_connection

from . import SmlBase, SmlSequence

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class SmlSerialProtocol(SmlBase, asyncio.Protocol):
    _BAUD_RATE = 9600

    def __init__(self, url, dispatch, wait_time=120):
        SmlBase.__init__(self)
        asyncio.Protocol.__init__(self)
        self._dispatch = dispatch
        self._url = urlparse(url)
        self._transport = None
        self._loop = None
        self._running = False
        self._buf = b''
        self._lock = None
        self._last_update = 0
        self._timeout_delay = wait_time
        self._watchdog = None

    async def _resume_reading(self, delay):
        await asyncio.sleep(delay)
        self._transport.resume_reading()

    def _delay_reading(self, delay):
        self._transport.pause_reading()
        asyncio.ensure_future(self._resume_reading(delay), loop=self._loop)

    def data_received(self, data: bytes):
        self._buf += data
        delay = 0.5
        self._last_update = time.time()

        while True:
            res = self.parse_frame(self._buf)
            end = res.pop(0)
            self._buf = self._buf[end:]

            if not res:
                break

            for msg in res[0]:
                body = msg.get('messageBody')
                if body:
                    self._dispatch(body)

            delay = 1

        self._delay_reading(delay)

    def connection_lost(self, exc: Optional[Exception]):
        logger.debug('port closed')
        self._transport = None
        if self._running and not self._lock.locked():
            asyncio.ensure_future(self._reconnect(), loop=self._loop)

    async def _create_connection(self):
        if self._url.scheme == 'socket':
            kwargs = {
                'host': self._url.hostname,
                'port': self._url.port,
            }
            coro = self._loop.create_connection(lambda: self, **kwargs)
        else:
            kwargs = {
                'url': self._url.geturl(),
                'baudrate': self._BAUD_RATE,
            }
            coro = create_serial_connection(self._loop, lambda: self, **kwargs)
        return await coro

    async def _reconnect(self, delay: int = 10):
        async with self._lock:
            await self._disconnect()
            await asyncio.sleep(delay)
            try:
                async with asyncio.timeout(5):
                    self._transport, _ = await self._create_connection()
            except (BrokenPipeError, ConnectionRefusedError,
                    SerialException, asyncio.TimeoutError) as exc:
                logger.warning(exc)
                asyncio.ensure_future(self._reconnect(), loop=self._loop)
            else:
                logger.info('Connected to %s', self._url.geturl())
                if self._timeout_delay:
                    self._last_update = time.time()
                    self._watchdog = asyncio.create_task(self._timeout())

    async def connect(self, loop=None):
        if self._running:
            return

        if not loop:
            loop = asyncio.get_event_loop()

        self._loop = loop
        self._lock = asyncio.Lock()
        self._running = True
        await self._reconnect(delay=0)

    async def _disconnect(self):
        if self._watchdog and not self._watchdog.done():
            self._watchdog.cancel()
        if self._transport:
            self._transport.abort()
            self._transport = None

    async def _timeout(self):
        while True:
            last_update = self._last_update
            sleep_time = last_update + self._timeout_delay - time.time()
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
                if last_update != self._last_update:
                    continue
            logger.warning(
                'Timeout while waiting for meter data. Please check reading device. Restarting edl21'
            )
            self.connection_lost(TimeoutError())
            return


class SmlHttpProtocol(SmlBase):
    def __init__(self, url, dispatch, poll_interval=2):
        super().__init__()
        self._dispatch = dispatch
        self._url = url
        self._poll_interval = poll_interval
        self._task = None

    async def _poll(self):
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(trust_env=True, timeout=timeout) as session:
            while not self._task.done():
                async with session.get(self._url) as resp:
                    data = await resp.read()

                    res = self.parse_frame(data)
                    end = res.pop(0)
                    if res:
                        for msg in res[0]:
                            body = msg.get('messageBody')
                            if body:
                                self._dispatch(body)

                await asyncio.sleep(self._poll_interval)

    async def connect(self, loop=None):
        self._task = asyncio.create_task(self._poll())


class SmlProtocol:
    def __init__(self, url, **kwargs):
        self._listeners = []
        self._url = urlparse(url)
        if self._url.scheme in ('http', 'https'):
            self._impl = SmlHttpProtocol(url, self._dispatch, **kwargs)
        else:
            self._impl = SmlSerialProtocol(url, self._dispatch, **kwargs)

    def _dispatch(self, message_body: SmlSequence):
        for listener, types in self._listeners:
            if not types or type(message_body).__name__ in types:
                listener(message_body)

    def add_listener(self, listener, types: list):
        self._listeners.append((listener, types))

    def remove_listener(self, listener, types: list):
        self._listeners.remove((listener, types))

    async def connect(self, loop=None):
        await self._impl.connect(loop)
