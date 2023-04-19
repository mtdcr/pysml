#
# Copyright (c) 2023 Andreas Oberritter
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
# Useful documents:
# https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/TR-03109-1_Anlage_Feinspezifikation_Drahtgebundene_LMN-Schnittstelle_Teilb.pdf?__blob=publicationFile&v=2
# https://www.vde.com/resource/blob/951000/252eb3cdf1c7f6cdea10847be399da0d/fnn-lastenheft-edl-1-0-2010-01-13-data.pdf
# https://www.dlms.com/files/Blue_Book_Edition_13-Excerpt.pdf
#

import logging
import re
from collections import namedtuple
from typing import Generator, Optional, Tuple
import bitstring

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


def crc16_generate_table() -> Generator[int, None, None]:
    for i in range(256):
        for _ in range(8):
            i = (i >> 1) ^ (0x8408 * (i & 1))
        yield i


class Crc:
    __CRC16_TABLE = tuple(crc16_generate_table())

    @staticmethod
    def crc16(octets: bytes) -> int:
        crc = 0xffff
        for octet in octets:
            crc = (crc >> 8) ^ Crc.__CRC16_TABLE[(crc ^ octet) & 0xff]
        crc ^= 0xffff
        return ((crc << 8) | (crc >> 8)) & 0xffff

    @staticmethod
    def verify_fcs(octets: bytes) -> bool:
        """RFC 1662, C.2. „16-bit FCS Computation Method“"""
        return Crc.crc16(octets) == 0x470f


class SmlParserError(Exception):
    pass


class SmlSequence(dict):
    def __init__(self, fields: tuple, values: list) -> None:
        super().__init__(zip(fields, [item.value for item in values]))

        for key in fields:
            if self[key] == b'':
                del self[key]


class SmlSequenceOf(list):
    def __init__(self, seq_type: SmlSequence, items: list) -> None:
        super().__init__()
        dzg_workaround = False

        for item in items:
            obj = seq_type(item.value)
            name = obj.get("objName")
            value = obj.get("value")

            # Slightly unsafe workaround for DZG meters incorrectly transmitting
            # some positive values as signed integers with MSB set.
            # https://github.com/jmberg/libsml/commit/81c4026e3d94f7a384cdd89f62a727b83269cdec
            if name and value:
                if name == "1-0:96.1.0*255" and value.startswith("1 DZG 00 "):
                    dzg_workaround = True
                elif dzg_workaround and name == "1-0:16.7.0*255" and value < 0 and len(item.value) >= 6:
                    bits = item.value[5].bits
                    if len(bits) in (8, 16, 24):
                        obj["value"] = bits.uintbe
                        obj.scale_value()

            if "scaler" in obj:
                del obj["scaler"]

            self.append(obj)


class SmlChoice:
    @staticmethod
    def create(choices: dict, items: list) -> SmlSequence:
        if len(items) != 2:
            raise SmlParserError('Invalid SML choice')

        klass = choices.get(items[0].value)
        if klass and klass in globals():
            return globals()[klass](items[1].value)

        return items


class SmlUnit(str):
    __UNITS = {
        1: 'a',
        2: 'mo',
        3: 'wk',
        4: 'd',
        5: 'h',
        6: 'min',
        7: 's',
        8: '°',
        9: '°C',
        10: 'currency',
        11: 'm',
        12: 'm/s',
        13: 'm³',
        14: 'm³',
        15: 'm³/h',
        16: 'm³/h',
        17: 'm³/d',
        18: 'm³/d',
        19: 'l',
        20: 'kg',
        21: 'N',
        22: 'Nm',
        23: 'Pa',
        24: 'bar',
        25: 'J',
        26: 'J/h',
        27: 'W',
        28: 'VA',
        29: 'var',
        30: 'Wh',
        31: 'VAh',
        32: 'varh',
        33: 'A',
        34: 'C',
        35: 'V',
        36: 'V/m',
        37: 'F',
        38: 'Ω',
        39: 'Ωm²/m',
        40: 'Wb',
        41: 'T',
        42: 'A/m',
        43: 'H',
        44: 'Hz',
        45: '1/(Wh)',
        46: '1/(varh)',
        47: '1/(VAh)',
        48: 'V²h',
        49: 'A²h',
        50: 'kg/s',
        51: 'S',
        52: 'K',
        53: '1/(V²h)',
        54: '1/(A²h)',
        55: '1/m³',
        56: '%',
        57: 'Ah',
        60: 'Wh/m³',
        61: 'J/m³',
        62: 'Mol%',
        63: 'g/m³',
        64: 'Pas',
        65: 'J/kg',
        66: 'g/cm²',
        67: 'arm',
        70: 'dBm',
        71: 'dBµV',
        72: 'dB',
    }

    @staticmethod
    def create(value) -> str:
        return SmlUnit.__UNITS.get(value)


class SmlOpenResponse(SmlSequence):
    __FIELDS = (
        'codepage',
        'clientId',
        'reqFileId',
        'serverId',
        'refTime',
        'smlVersion',
    )

    def __init__(self, values: list) -> None:
        super().__init__(self.__FIELDS, values)


class SmlCloseResponse(SmlSequence):
    __FIELDS = (
        'globalSignature',
    )

    def __init__(self, values: list) -> None:
        super().__init__(self.__FIELDS, values)


class SmlListEntry(SmlSequence):
    __FIELDS = (
        'objName',
        'status',
        'valTime',
        'unit',
        'scaler',
        'value',
        'valueSignature',
    )

    def __init__(self, values: list) -> None:
        super().__init__(self.__FIELDS, values)

        name = self.get('objName')
        if name and len(name) == 6:
            self['objName'] = '%d-%d:%d.%d.%d*%d' % (
                name[0], name[1], name[2], name[3], name[4], name[5]
            )

        unit = self.get('unit')
        if unit:
            self['unit'] = SmlUnit.create(unit)

        self.scale_value()
        value = self["value"]

        # Electricity ID
        if name in (b'\x01\x00\x00\x00\x09\xff', b'\x01\x00\x60\x01\x00\xff') and \
           isinstance(value, bytes) and len(value) > 0:
            if value[0] in (9, 10) and len(value) == 10:
                self['value'] = '%X %s %02X %d' % (
                    value[1], value[2:5].decode('latin1'), value[5],
                    int.from_bytes(value[6:], byteorder='big')
                )
            else:
                self['value'] = '-'.join(['%02X' % x for x in value])

        # Manufacturer ID
        elif name == b'\x81\x81\xc7\x82\x03\xff' and \
             isinstance(value, bytes) and len(value) == 3:
            self['value'] = self['value'].decode('latin1')

        # Public Key
        elif name == b'\x81\x81\xc7\x82\x05\xff' and \
             isinstance(value, bytes):
            self['value'] = self['value'].hex()

    def scale_value(self):
        scaler = self.get('scaler')
        value = self.get('value')
        if scaler and value:
            if scaler < 0:
                self['value'] = value / 10 ** abs(scaler)
            else:
                self['value'] = value * 10 ** scaler


class SmlGetListResponse(SmlSequence):
    __FIELDS = (
        'clientId',
        'serverId',
        'listName',
        'actSensorTime',
        'valList',
        'listSignature',
        'actGatewayTime',
    )

    def __init__(self, values: list) -> None:
        super().__init__(self.__FIELDS, values)
        self['valList'] = SmlSequenceOf(SmlListEntry, self['valList'])


class SmlMessage(dict):
    __FIELDS = (
        'transactionId',
        'groupNo',
        'abortOnError',
        'messageBody',
        'crc16',
        'endOfSmlMsg',
    )

    __CHOICES = {
        0x0100: 'SmlOpenRequest',
        0x0101: 'SmlOpenResponse',
        0x0200: 'SmlCloseRequest',
        0x0201: 'SmlCloseResponse',
        0x0300: 'SmlGetProfilePackRequest',
        0x0301: 'SmlGetProfilePackResponse',
        0x0400: 'SmlGetProfileListRequest',
        0x0401: 'SmlGetProfileListResponse',
        0x0500: 'SmlGetProcParameterRequest',
        0x0501: 'SmlGetProcParameterResponse',
        0x0600: 'SmlSetProcParameterRequest',
        0x0601: 'SmlSetProcParameterResponse',
        0x0700: 'SmlGetListRequest',
        0x0701: 'SmlGetListResponse',
        0xff01: 'SmlAttentionResponse',
    }

    ListItem = namedtuple('ListItem', ['length', 'value', 'bits'])

    def __init__(self, bits: bitstring.ConstBitStream) -> None:
        super().__init__()
        self._bits = bits
        start = self._bits.pos

        logger.debug("[*] MESSAGE: %s", self._bits[start:])

        tag, length, tlsize = self._read_tag_length()
        if tag != 7 or length != 6 or tlsize != 1:
            raise SmlParserError('Message does not start with 0x76')

        values = self._read_list(length)
        for key, val in zip(self.__FIELDS, values):
            self[key] = val

        if self['endOfSmlMsg'].value is not None:
            raise SmlParserError('Invalid value for endOfSmlMsg')

        end = self._bits.pos
        msg_bytes = self._bits[start:end].bytes
        if Crc.crc16(msg_bytes[:-(self['crc16'].length + 1)]) != self['crc16'].value:
            raise SmlParserError('CRC16 mismatch')

        self['messageBody'] = SmlChoice.create(self.__CHOICES,
                                               self['messageBody'].value)

        logger.debug("[*] CONSUMED: %s", msg_bytes.hex())
        logger.debug("[*] RESULT (%d bits left): %s",
                     (self._bits.length - self._bits.pos), self)

    def _read_tag_length(self) -> Tuple[int, int, int]:
        fmt = ['bool', 'uint:3', 'uint:4']

        more, tag, length = self._bits.readlist(fmt)
        consumed = 1

        while more:
            more, syntax, nextlength = self._bits.readlist(fmt)
            if syntax != 0:
                raise SmlParserError('Unhandled TL syntax')

            length = length << 4 | nextlength
            consumed += 1

        return tag, length, consumed

    def _read_list(self, count: int, nesting: int = 0) -> list:
        res = []
        logger.debug("%s[*] List of %d items", nesting * ' ', count)

        for i in range(count):
            logger.debug("%s[*] Item %d of %d", nesting * ' ', i + 1, count)

            tag, length, tlsize = self._read_tag_length()
            logger.debug("%s[+] Tag: %#x, Len: %d", nesting * ' ', tag, length)

            if tag in (0, 5, 6) and length >= tlsize:
                bits = self._bits.read('bits:%d' % ((length - tlsize) * 8))
            else:
                bits = None

            if tag == 0 and length == 0:
                value = None
            elif tag == 0 and length >= tlsize:
                value = bits.bytes
            elif tag == 5 and length > tlsize:
                value = bits.intbe
            elif tag == 6 and length > tlsize:
                value = bits.uintbe
            elif tag == 7 and length > 0:
                value = self._read_list(length, nesting + 1)
            else:
                raise SmlParserError('Unknown TL field')

            logger.debug('%s[+] Value: %s', nesting * ' ', value)
            res.append(SmlMessage.ListItem(length, value, bits))

        assert len(res) == count
        return res


class SmlFrame(list):
    def __init__(self, octets: bytes) -> None:
        super().__init__()

        self.bits = bitstring.ConstBitStream(octets)
        while self.bits.pos < self.bits.length:
            self.append(SmlMessage(self.bits))


class SmlBase:
    __MSG_ESC = b'\x1b\x1b\x1b\x1b'
    __MSG_START = b'\x01\x01\x01\x01'
    __MSG_END = b'\x1a'

    # __PATTERN = re.compile(
    #    b'(?P<esc_start>%s)' % __MSG_ESC +
    #    b'(?P<start>%s)' % __MSG_START +
    #    b'(?P<data>(?:(?!%s).|%s)+)' % (__MSG_ESC, __MSG_ESC * 2) +
    #    b'(?P<esc_end>%s)' % __MSG_ESC +
    #    b'(?P<end>%s...)' % __MSG_END,
    #    re.DOTALL)
    __PATTERN = re.compile(b'%s%s(?:(?!%s).|%s)+%s%s...' %
                           (__MSG_ESC, __MSG_START, __MSG_ESC,
                            __MSG_ESC * 2, __MSG_ESC, __MSG_END),
                           re.DOTALL)

    @staticmethod
    def __unescape(buf: bytes) -> bytes:
        return buf.replace(SmlBase.__MSG_ESC * 2, SmlBase.__MSG_ESC)

    @staticmethod
    def parse_frame(buf: bytes) -> Tuple[int, Optional[SmlFrame]]:
        start = 0
        end = 0

        for match in SmlBase.__PATTERN.finditer(buf):
            if match.start() > start:
                logger.debug('Skipped %d bytes at offset %d: [%s]',
                             match.start() - start, start,
                             buf[start:match.start()].hex())

            frame = match.group(0)
            padding = frame[-3]
            if padding <= 4 and Crc.verify_fcs(frame):
                obj = SmlFrame(SmlBase.__unescape(frame[8:-8-padding]))
                return [match.end(), obj]

            start = match.start()
            assert match.end() > end
            end = match.end()

        return [end]
