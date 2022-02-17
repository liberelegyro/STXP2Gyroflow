#!/bin/env python
from struct import *
from Crypto.Cipher import AES
from hexdump import *
import numpy

def get_key_indices(max_index, chunk_idx, chunk_idx2, num1, num2, multiplier, num_ints):
    some_num = num1 * (chunk_idx2 + 1)
    some_float = numpy.float32(chunk_idx2 + 4) * numpy.float32(multiplier)
    out = []

    for i in range(num_ints):
        num = (numpy.float32(chunk_idx + some_num) * some_float) + numpy.float32(num2 * chunk_idx2)
        while (True):
            final_int = int(num) % max_index
            chunk_idx = final_int
            if final_int not in out:
                break
            num = final_int + 1

        out.append(final_int)
    return out

def swapIntBytes(buf):
    buf = bytearray(buf)
    buf[0::4], buf[1::4], buf[2::4], buf[3::4] = buf[3::4], buf[2::4], buf[1::4], buf[0::4]
    return buf

input_filename = sys.argv[1]
temporary_filename = input_filename + ".dec"

inf  = open(input_filename, "rb")
tempf = open(temporary_filename, "wb")

first_aes = AES.new(b'\x1E\xD0\xD8\x00\x7A\x84\x5A\xD8\x92\xC8\x14\x00\x0E\x5C\x38\xD8\xF0\xB4\xA2\x00\x42\x34\x26\x98\x88\x28\xB2\x40\xD4\xC8\xD4\xC0', AES.MODE_ECB)
key_aes   = AES.new(b'\xbc\xd8\x40\x00\xcc\x70\x1c\x70\x5c\xf0\x58\x20\x98\xd8\x6c\xc0\x80\x40\xe4\x80\xac\x48\x90\x50\x4c\x58\x8c\x80\x50\xd0\x2c\xd0', AES.MODE_ECB)

i = 0
while (True):
    chunk = swapIntBytes(inf.read(16384))
    if len(chunk) < 16384:
        break
    dec = first_aes.decrypt(chunk)

    key_chunk = swapIntBytes(dec[15648:])

    ki = get_key_indices(736, i, i, 7, 3, 1.5, 32)
    key2 = []
    for x in ki:
        key2.append(key_chunk[x])

    next_key = key_aes.decrypt(bytes(key2))
 
    dec = AES.new(next_key, AES.MODE_ECB).decrypt(dec[0:15648])

    tempf.write(swapIntBytes(dec[0:15624]))
    i = i + 1
inf.close()
tempf.close()

# Help outputing a linear timestamp
timetrack = dict(prev=0, total=0)

def linearizeTimestamp(ts):
    if ts < timetrack['prev']:
        timetrack['total'] += 20.0 - timetrack['prev'] + ts
    else:
        timetrack['total'] += ts - timetrack['prev']
    timetrack['prev'] = ts
    return int(timetrack['total'])

# gyro scaling function
def gyroScaling(x):
    return int(x* 65536) # the constant may need to be adjusted, try "1000" if it fails

# gyroflow CSV output

out = open(input_filename + ".gcsv", "w")

out.write("""GYROFLOW IMU LOG
version,1.1
id,steadXP
orientation,xyz
tscale,0.001
gscale,0.001
t,gx,gy,gz
""")

# output one line of the CSV file
def dump(ts, gyro):
    out.write("%d, %d, %d, %d\n" % (
        linearizeTimestamp(ts),
        gyroScaling(gyro[0]),
        gyroScaling(gyro[1]),
        gyroScaling(gyro[2]))
        )

# Read the decoded file
with open(temporary_filename, "rb") as f:
    header = f.read(48)
    header = swapIntBytes(AES.new(b'\x3A\xBC\x12\x00\x1C\xD8\xDC\x78\x40\xD4\xC0\x10\x0C\x24\xDA\x00\xFC\x88\x38\x00\xCA\x90\xF0\x50\xAA\xE0\x80\x80\x40\x7C\xA6\xC0', AES.MODE_ECB).decrypt(swapIntBytes(header[0:16]))) + header[16:]
    # Header size: 48 bytes
    # 16 bytes - swap, AES decrypt, swap again
    # 4 bytes - int32 Key_CRYPT
    # 4 bytes - int32 QLAP_Index_File
    # 2 bytes - int16 firmware version
    # 1 byte - device is gopro
    # 1 byte - device is genlock file
    #print('Header:'), hexdump(header)

    while True:
        # Item size: 24 bytes
        item = f.read(24)
        if len(item) != 24:
            break
        record = list(unpack(">BHIBI", item[0:12]) + unpack("<fff", item[12:]))
        record[2] /= 1000.0
        record[4] /= 1000.0
        dump(record[2], record[-3:])
out.close()
