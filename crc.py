from crccheck.crc import Crc16CcittFalse

data = bytearray.fromhex("00 01 02 00 00 00 1A 00 02 FD 00 0C 72 07 64 02 80 3D 72 07 66 FD 7F 1B")

tmp = Crc16CcittFalse.calchex(data)
pass
