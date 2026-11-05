from . import packetmap
import asyncio
import errno
from socket import error as socket_error
#from hexdump import hexdump # for debugging

def MessageObjectToMessagePacket(messageObject, mapName, atVersion):
    if(atVersion.value == 5):
        messageString = "80b001c0";
        dataPayload = hex(packetmap.SettingValueTranslator.NamedValueToRawValue("MessageType", messageObject.MessageType, 5))[2:]+"00000000040001";
        groupControlPacketLocationMap = packetmap.DataLocationTranslator.map[5][mapName]
    
    elif(atVersion.value == 4):
        messageString = "80b001";
        messageString += hex(packetmap.SettingValueTranslator.NamedValueToRawValue("MessageType", messageObject.MessageType))[2:]
        dataPayload = "";
        groupControlPacketLocationMap = packetmap.DataLocationTranslator.map[4][mapName]
    
    packetInfoAttributes = [attr for attr in groupControlPacketLocationMap.keys()]
    binaryMessagePayloadString = "";
    for attribute in packetInfoAttributes:
        binaryMessagePayloadString = AddMapValueToBinaryValue(binaryMessagePayloadString, groupControlPacketLocationMap[attribute], messageObject.MessageValues[attribute])

    dataPayload += format(int(binaryMessagePayloadString, 2), '08x');
    dataLength = len(dataPayload) / 2;
    lengthString = "0000"[0: 4 - (len(hex((int(dataLength)))[2:]))] + hex((int(dataLength)))[2:];

    if(atVersion.value == 5):
        messageString += lengthString
        messageString += dataPayload
    elif(atVersion.value == 4):
        messageString += lengthString + dataPayload
    return messageString

def AddMapValueToBinaryValue(binaryMessagePayloadString, map, value):
    byteNumber = int(map.split(":")[0])
    length = 8;
    #spec counts bytes backwards so so do we
    bitmaskstart = length - (int(map.split(":")[1].split("-")[1]) - 1);
    bitmaskend = length - (int(map.split(":")[1].split("-")[0]) - 1);

    #binaryMessage needs to be at least as long as (byteNumber - 1) * 8 + bitmaskstart, so add as many zeroes as required to make that happen

    while(len(binaryMessagePayloadString) < (byteNumber - 1) * 8 + (bitmaskstart - 1)):
        binaryMessagePayloadString += "0"

    binOfValueAsString = bin(value)[2:];
    lengthNeededForBinValue = bitmaskend - (bitmaskstart - 1);
    binaryMessagePayloadString = binaryMessagePayloadString + "00000000"[0: lengthNeededForBinValue - len(binOfValueAsString)] + binOfValueAsString
    return binaryMessagePayloadString

def TranslateMapValueToValue(groupChunk, map):
    byteNumber = int(map.split(":")[0])
    length = 8;
    if(int(map.split(":")[1].split("-")[1]) > 8):
        length = 16;
    #spec counts bytes backwards so so do we
    bitmaskstart = length - (int(map.split(":")[1].split("-")[1]) - 1);
    bitmaskend = length - (int(map.split(":")[1].split("-")[0]) - 1);
    byteAsString = bin(groupChunk[byteNumber - 1])
    byteStringAdjusted = "00000000"[0: 8 - (len(byteAsString) - 2)] + byteAsString[2:];

    if(length > 8):
        byteStringAdjusted += ("00000000"[0: 8 - (len(bin(groupChunk[byteNumber])) - 2)] + bin(groupChunk[byteNumber])[2:]);

    byteSegment = byteStringAdjusted[bitmaskstart - 1: bitmaskend];
    byteSegmentAsValue = int(byteSegment, 2)
    return byteSegmentAsValue

#might raise a socket or os error if connection fails
async def SendMessagePacketToAirtouch(messageString, ipAddress, atVersion, atPort):
    #add header, add crc
    if(atVersion.value == 5):
        messageString = "555555aa" + messageString + format(crc16(bytes.fromhex(messageString)), '08x')[4:]
    else:
        messageString = "5555" + messageString + format(crc16(bytes.fromhex(messageString)), '08x')[4:]
    #hexdump(bytearray.fromhex(messageString)) # for debugging
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ipAddress, atPort), timeout=TIMEOUT_SECONDS)
    try:
        writer.write(bytearray.fromhex(messageString))
        await writer.drain()
        response = await asyncio.wait_for(ReadFrame(reader, atVersion), timeout=TIMEOUT_SECONDS)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    #hexdump(response) # for debugging
    return response;

TIMEOUT_SECONDS = 2.0
BUFFER_SIZE = 4096
# Bytes before the data block: header + address(2) + message id(1) + message type(1) + data length(2)
HEADER_LENGTH = {4: 2 + 6, 5: 4 + 6}
CRC_LENGTH = 2

async def ReadFrame(reader, atVersion):
    """Read until a whole frame (header, declared data length and CRC) has arrived.

    A single read() can return a partial frame when the response spans several TCP segments,
    which previously got decoded as if it were complete.
    """
    headerLength = HEADER_LENGTH[atVersion.value]
    response = b""
    while True:
        chunk = await reader.read(BUFFER_SIZE)
        if not chunk:
            return response  # connection closed; caller validates what we have
        response += chunk
        if len(response) >= headerLength:
            dataLength = int.from_bytes(response[headerLength - 2:headerLength], byteorder='big')
            if len(response) >= headerLength + dataLength + CRC_LENGTH:
                return response

def ValidateAt4Frame(frame):
    """Return the data block of an AirTouch 4 frame, or raise ValueError if the frame is malformed.

    Frame layout: 0x5555 | address(2) | id(1) | type(1) | length(2) | data(length) | crc16(2).
    The CRC covers everything after the 0x5555 header up to the end of data.
    """
    headerLength = HEADER_LENGTH[4]
    if len(frame) < headerLength + CRC_LENGTH:
        raise ValueError(f"frame too short ({len(frame)} bytes): {frame.hex()}")
    if frame[0:2] != b'\x55\x55':
        raise ValueError(f"bad header: {frame.hex()}")
    dataLength = int.from_bytes(frame[headerLength - 2:headerLength], byteorder='big')
    frameLength = headerLength + dataLength + CRC_LENGTH
    if len(frame) < frameLength:
        raise ValueError(f"truncated frame (got {len(frame)} of {frameLength} bytes): {frame.hex()}")
    crcExpected = int.from_bytes(frame[headerLength + dataLength:frameLength], byteorder='big')
    crcActual = int(crc16(frame[2:headerLength + dataLength]))
    if crcExpected != crcActual:
        raise ValueError(f"CRC mismatch (expected {crcExpected:04x}, got {crcActual:04x}): {frame.hex()}")
    return frame[headerLength:headerLength + dataLength]

import numpy as np

def crc16(data: bytes):
    '''
    CRC-16-ModBus Algorithm
    '''
    data = bytearray(data)
    poly = 0xA001
    crc = 0xFFFF
    for b in data:
        crc ^= (0xFF & b)
        for _ in range(0, 8):
            if (crc & 0x0001):
                crc = ((crc >> 1) & 0xFFFF) ^ poly
            else:
                crc = ((crc >> 1) & 0xFFFF)

    return np.uint16(crc)