""" Read HDLC """
import sys
import os
import binascii
import sources.ebilockcmain as eb

telegramms = []
#(os.path.abspath(__file__))
# читаем HDLC данные
def read_hdlc():
    base_dir = os.path.abspath(os.curdir)
    file_hdlc = base_dir + '\\sources\\hdlc.dat'
    DLE = 0x10
    STX = 0x02
    ETX = 0x83
    source_hex = ""
    
    # если файл существует
    if os.path.isfile(file_hdlc):
        try:
            pass
            with open(file_hdlc, "rb") as hdlc:  # читаем  файл
                source_hex = hdlc.read()
        except Exception:
            print("\nПроблема с чтением файла: " + file_hdlc + "\n")
    else:
        print("\nОтсутствует файл: %s\n" % file_hdlc)

    tmp_hex = []
    key = 0
    for i in range(len(source_hex)):
        if source_hex[key] == DLE and source_hex[key + 1] == STX:
            tmp_hex = source_hex[key+2:]
            key2 = 0
            packet = []
            for key2 in range(len(tmp_hex)):
                if tmp_hex[key2] == ETX and tmp_hex[key2+1] == DLE:
                    telegramms.append(tmp_hex[:key2-1])
                    key += key2 + 3
                    break
                if key > len(tmp_hex):
                    break
            packet.append(hex(tmp_hex[key2]))

    print("count {}".format(len(telegramms)))


read_hdlc()

for tlg in telegramms:
    ebl = eb.Edilock.from_hdlc(tlg)
    ebl.check_telegramm()
    print("*"*5)
    pass
pass
