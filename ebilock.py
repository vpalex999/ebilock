#  import binascii
from crccheck.crc import Crc16CcittFalse

""" Функция принимает телеграмму списком выводит в
консоль основные данные и проверяет их корректность
"""

# Описание структуры  Заголовка и тела сетевого пакета
desc_header_packet = {
    "size": 8,  # количество 2х байтовых слов в заголовке - константа
    "ID_SOURCE_IND": 0,  # ID отправителя
    "ID_DEST_IND": 1,  # ID получателя
    "TYPE_PACKET_IND": 2,  # Тип пакета
    "START_DATA_IND": 3,  # Длинна пакета 4 2х байтовых слова - начало
    "END_DATA_IND": 6,  # Длинна пакета 4 2х байтовых слова - конец
    "NUL_BYTE_IND": 7,  # Нулевой байт - всегда 00
    "PACKET_COUNT_A_IND": 8,  # Счётчик А пакета
    "PACKET_COUNT_B_IND": 9,  # Счётчик В пакета
    "START_SIZE_AB_IND": 10,  # Размер блока телеграм - начала
    "END_SIZE_AB_IND": 12,  # Размер блока телеграм - конец
    "ID":  # ID идентификатор отправителя или получателя
    {"0": "IPU_GATE_RF",  # Ebilock940
     "1": "EHA"  # Внешняя система
     },
    "TYPE_ID":  # Тип телеграммы
    {"2": "2 - накачка",
     "3": "3 - передача статусов",
     "4": "4 - пустая накачка",
     "5": "5 - IPU_GATE_RF -> OK",
     "6": "6 - OK -> IPU_GATE_RF"
     },
    "TLG_AB":
    {
     "OK_START": 0,
     "OK_END": 1,
     "ML_CO": 2,
     "COUNT_AB": 3,
     "co":
     {
      4: "4 - приказ, телеграмма А (отправитель Ebilock950 R4)",
      6: "6 - приказ, телеграмма B (отправитель Ebilock950 R4)",
      8: "8 - статус, телеграмма А (отправитель EHA)",
      "C": "C - статус, телеграмма B (отправитель EHA)"
     },
    },
    }

# Описание структуры блока телеграм
desc_telegramm_ab = {
    "pass": ""
}


telegramm_decode = {
        "PACKET": "",
        "ID_SOURCE": "",
        "ID_DEST": "",
        "TYPE_PACKET": "",
        "LENGTH_PACKET": "",
        "PACKET_COUNT_A": "",
        "PACKET_COUNT_B": "",
        "SIZE_AB": "",
        "TELEGRAMM_AB": "",
        "RC": "",
        "TLG_A": {
            "BODY_TLG": "",
            "ADDR_OK": "",
            "LOOP_OK": "",
            "AREA_OK": "",
            "HUB_OK": "",
            "NUM_OK": "",
            "ML_CO": "",
            "SIZE": "",
            "TYPE_TLG": "",
            "COUNT": "",
            "DATA": "",
            "RC": ""
        },
        "TLG_B": {},
    }


# проверка на соответствие двубайтовых последовательностей
def check_byte_flow(telegramm):
    status = True
    sources = telegramm.split(' ')
    if len(sources) < 26:
        print("Invalid package '{}' 2xByte, min = 26 2xByte".format(len(sources)))
        return False
    for item in sources:
        if item == '':
            status = False
            print("Empty value by index '{}'".format(sources.index("")))
            break
        if len(item) != 2:
            status = False
            print("Length value '{}' is not equal to 2".format(item))
            break
    telegramm_decode["PACKET"] = sources
    return status


def check_header_packet(telegramm):

    status = True
    sources = telegramm.split(' ')

    # проверка ID отправителя
    tmp = int(sources[desc_header_packet["ID_SOURCE_IND"]], 16)
    if tmp > 1:
        print("Error!  ID_SOURCE = '{}' should be between 0 or 1".format(tmp))
        status = False
    else:
        telegramm_decode["ID_SOURCE"] = desc_header_packet["ID"][str(tmp)]

    # проверка ID получателя
    tmp = int(sources[desc_header_packet["ID_DEST_IND"]], 16)
    if tmp > 1:
        print("Error!  ID_DEST = '{}' should be between 0 or 1".format(tmp))
        status = False
    else:
        telegramm_decode["ID_DEST"] = desc_header_packet["ID"][str(tmp)]

    # Проверка типа пакета
    tmp = int(sources[desc_header_packet["TYPE_PACKET_IND"]], 16)
    key_stat = False
    type_id = desc_header_packet["TYPE_ID"]
    for key, val in type_id.items():
        if int(key) == tmp:
            telegramm_decode["TYPE_PACKET"] = val
            key_stat = True
            break
    if not key_stat:
        print("Value '{}' out of range type telegramm".format(tmp))
        status = False

    # Проверка длинны пакета
    tmp = int(''.join(sources[desc_header_packet["START_DATA_IND"]:desc_header_packet["END_DATA_IND"] + 1]), 16)
    if tmp != len(sources):
        print("Error Checking length packet!!! data length = '{0}', actual length = '{1}'".format(tmp, len(sources)))
        status = False
    else:
        telegramm_decode["LENGTH_PACKET"] = tmp
    # Проверка NULL байта
    tmp = int(sources[desc_header_packet["NUL_BYTE_IND"]])
    if tmp != 0:
        print("Invalid header structure, Zero byte value = '{}', must be 0".format(tmp))
        status = False
    return status


def check_packet_count_ab(telegramm):
    status = True
    sources = telegramm.split(' ')

    tmp = int(sources[desc_header_packet["PACKET_COUNT_A_IND"]], 16)
    if tmp > 255:
        print("Value count_A - '{}' out of range 0 - 255.".format(tmp))
        status = False
    else:
        telegramm_decode["PACKET_COUNT_A"] = tmp

    tmp = int(sources[desc_header_packet["PACKET_COUNT_B_IND"]], 16)
    if tmp > 255:
        print("Value count_B - '{}' out of range 0 - 255.".format(tmp))
        status = False
    else:
        telegramm_decode["PACKET_COUNT_B"] = tmp

    return status


def check_size_ab(telegramm):
    status = True
    sources = telegramm.split(' ')

    tmp = int(''.join(sources[desc_header_packet["START_SIZE_AB_IND"]:desc_header_packet["END_SIZE_AB_IND"]]), 16)
    if tmp > 4096:
        print("Too long data > 4096 bytes - '{}'".format(tmp))
        status = False
    else:
        telegramm_decode["SIZE_AB"] = tmp
    return status


def check_telegramm_ab(telegramm):
    status = True
    sources = telegramm.split(' ')
    start_ab = desc_header_packet["END_SIZE_AB_IND"]
    end_ab = int(telegramm_decode["SIZE_AB"]) + start_ab
    tmp = sources[start_ab:end_ab]
    telegramm_decode["TELEGRAMM_AB"] = tmp
    return status


def check_rc(telegramm):
    sources = telegramm.split(' ')
    start_ab = desc_header_packet["END_SIZE_AB_IND"]
    end_ab = int(telegramm_decode["SIZE_AB"]) + start_ab
    r_c = ''.join(sources[end_ab:])
    telegramm_decode["RC"] = r_c
    body_packet = bytearray.fromhex(''.join(sources[:end_ab]))
    get_check_rc = Crc16CcittFalse.calchex(body_packet)
    if r_c == get_check_rc.upper():
        return True
    else:
        return False


def check_count_packet(telegramm):

    if telegramm_decode["PACKET_COUNT_A"] + telegramm_decode["PACKET_COUNT_B"] == 255:
        return True
    else:
        return False


def check_telegramm(telegramm):
    if not check_byte_flow(telegramm) or not\
        check_header_packet(telegramm) or not\
            check_packet_count_ab(telegramm) or not\
            check_size_ab(telegramm) or not\
            check_telegramm_ab(telegramm) or not\
            check_rc(telegramm) or not\
            check_count_packet(telegramm):
        return False
    else:
        return True

def decode_ab(telegram_ab):
    

    

def read_telegramm(str_tel):
    pass

    # Преобразуем в список
    source = str_tel.split(' ')

    header_packet = {
        "size": 12,
        "ID": {"0": "IPU_GATE_RF", "1": "EHA"},
        "TYPE_ID": {"2": "накачка", "3": "передача статусов", "4": "пустая накачка"}
    }

    # telegramm_decode = {
    #     "ID_SOURCE": "",
    #     "ID_DEST": "",
    #     "TYPE_PACKET": "",
    #     "LENGTH_PACKET": "",
    #     "COUNT_A": "",
    #     "COUNT_B": "",
    #     "SIZE_AB": "",
    #     "RC": ""
    # }

    ml_co = {
        "co": {4: "4 - приказ, телеграмма А (отправитель Ebilock950 R4)",
               6: "6 - приказ, телеграмма B (отправитель Ebilock950 R4)",
               8: "8 - статус, телеграмма А (отправитель EHA)",
               "C": "C - статус, телеграмма B (отправитель EHA)"}
    }

    telegramm_decode["ID_SOURCE"] = header_packet["ID"][str(int(source[0]))]
    telegramm_decode["ID_DEST"] = header_packet["ID"][str(int(source[1]))]
    telegramm_decode["TYPE_PACKET"] = header_packet["TYPE_ID"][str(int(source[2]))]
    telegramm_decode["LENGTH_PACKET"] = str(int(''.join(source[3:7]), 16))
    telegramm_decode["COUNT_A"] = str(int(source[8], 16))
    telegramm_decode["COUNT_B"] = str(int(source[9], 16))
    telegramm_decode["SIZE_AB"] = str(int(''.join(source[10:12]), 16))
    telegramm_decode["RC"] = str(''.join(source[-2: int(''.join(source[3:7]), 16)]))

    print("Packet: {}".format(source))
    print("-- packet header --")
    print("header content: {}".format(source[:header_packet["size"]]))

    for key, val in telegramm_decode.items():
        print("{0}: {1}".format(key, val))

    print("-- Telegramm A/B --")
    print("Telegramm A/B: {}".format(source[12:-2]))

    def get_bit(string, ind, number):
        tmp = string[ind]
        bit = int(tmp[number], 16)
        return bit

    def get_ok(telegramm):
        tmp = get_bit(telegramm, 1, 1) - 1
        return tmp

    start_a = 12
    end_a = start_a + get_bit(source, 14, 0)
    start_b = end_a
    end_b = start_b + get_bit(source, start_b + 2, 0)
    telegramm_a = source[start_a: end_a]
    telegramm_b = source[start_b: end_b]

    def telegramm_x(telegramm, number):

        print("Telegramm {0}: {1}".format(number, telegramm))
        print("№ OK: {}".format(get_ok(telegramm)))
        print("Type: {}".format(ml_co["co"][get_bit(telegramm, 2, 1)]))
        print("Count_{0}: {1}".format(number, telegramm[3]))
        print("Data_{0}: {1}".format(number, ''.join(telegramm[4: -1])))
        print("Telegramm {0} RC: {1}".format(number, telegramm[len(telegramm)-1]))

    telegramm_x(telegramm_a, "A")
    telegramm_x(telegramm_b, "B")
