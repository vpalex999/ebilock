from crccheck.crc import Crc16CcittFalse

data = bytearray.fromhex("00 01 02 00 00 00 1A 00 02 FD 00 0C 72 07 64 02 80 3D 72 07 66 FD 7F 1B")

tmp = Crc16CcittFalse.calchex(data)
pass

#tmp = "00 85 8F 0A 9B 1E 14 91 B3 36\
# 3C B9 28 AD A7 22 E3 66 6C E9\
# 78 FD F7 72 50 D5 DF 5A CB 4E\
# 44 C1 43 C6 CC 49 D8 5D 57 D2\
# F0 75 7F FA 6B EE E4 61 A0 25\
# 2F AA 3B BE B4 31 13 96 9C 19\
# 88 0D 07 82 86 03 09 8C 1D 98\
# 92 17 35 B0 BA 3F AE 2B 21 A4\
# 65 E0 EA 6F FE 7B 71 F4 D6 53\
# 59 DC 4D C8 C2 47 C5 40 4A CF\
# 5E DB D1 54 76 F3 F9 7C ED 68\
# 62 E7 26 A3 A9 2C BD 38 32 B7\
# 95 10 1A 9F 0E 8B 81 04 89 0C\
# 06 83 12 97 9D 18 3A BF B5 30\
# A1 24 2E AB 6A EF E5 60 F1 74\
# 7E FB D9 5C 56 D3 42 C7 CD 48\
# CA 4F 45 C0 51 D4 DE 5B 79 FC\
# F6 73 E2 67 6D E8 29 AC A6 23\
# B2 37 3D B8 9A 1F 15 90 01 84\
# 8E 0B 0F 8A 80 05 94 11 1B 9E\
# BC 39 33 B6 27 A2 A8 2D EC 69\
# 63 E6 77 F2 F8 7D 5F DA D0 55\
# C4 41 4B CE 4C C9 C3 46 D7 52\
# 58 DD FF 7A 70 F5 64 E1 EB 6E\
# AF 2A 20 A5 34 B1 BB 3E 1C 99\
# 93 16 87 02 08 8D"
#
#crc8TableA = bytearray.fromhex(tmp)

test_byte = bytearray.fromhex("01")
test_byte1 = bin(-6)
pass
