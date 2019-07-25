#!/usr/bin/env python3
#
# Copyright (c) 2019 Andreas Oberritter
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
from sys import argv
from sml import SmlSequence, SmlGetListResponse
from sml.asyncio import SmlProtocol

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SmlEvent:
    def __init__(self):
        self._cache = {}

    def event(self, message_body: SmlSequence) -> None:
        assert isinstance(message_body, SmlGetListResponse)
        for val in message_body.get('valList', []):
            name = val.get('objName')
            if name:
                if self._cache.get(name) != val:
                    self._cache[name] = val
                    print(val)


def main(url):
    handler = SmlEvent()
    proto = SmlProtocol(url)
    proto.add_listener(handler.event, ['SmlGetListResponse'])
    loop = asyncio.get_event_loop()
    loop.run_until_complete(proto.connect(loop))
    loop.run_forever()


if __name__ == '__main__':
    if len(argv) != 2:
        print('usage: %s socket://127.0.0.1:51945\n' % argv[0] +
              '   or: %s /dev/ttyS0' % argv[0])
        exit(1)

    main(argv[1])
    exit(0)
