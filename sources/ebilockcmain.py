from crccheck.crc import Crc16CcittFalse
from sources.crc8 import check_crc_8 as crc8
from sources.error import EbException


class Edilock(object):
    """ class Ebilock
    """
    def __init__(self, telegramm, hdlc=None):
            if hdlc is None:
                self.telegramm = telegramm.split(' ')
            else:
                self.telegramm = telegramm
            if not self._check_byte_flow():
                raise EbException("Error check flow")

    @classmethod
    def from_hdlc(cls, object):
        telegramm = []
        for item in object:
            telegramm.append("{:02x}".format(int(item), 16).upper())
        return cls(telegramm, "hdlc")

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
        {2: "2 - накачка",
         3: "3 - передача статусов",
         4: "4 - пустая накачка",
         5: "5 - IPU_GATE_RF -> OK",
         6: "6 - OK -> IPU_GATE_RF"
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
                "NUMBER_OK": "",
                "ML_CO": "",
                "SIZE": "",
                "type_co": "",
                "COUNT": "",
                "DATA": "",
                "RC": ""
            },
            "TLG_B": {},
            "STATUS_ZONE": ""
        }

    def _check_byte_flow(self):
        """ Verifying bytes in the packet stream\
        and writing a package to a dictionary.\n
        check_byte_flow("00, ff")\n
        ARG: String of bytes in hex.
        """

        status = True
        sources = self.telegramm
        if len(sources) < 20:
            print("Invalid package '{}' 2xByte, min = 26 2xByte".format(len(sources)))
            #return False
        for item in sources:
            if item == '':
                status = False
                print("Empty value by index '{}'".format(sources.index("")))
                break
            if len(item) != 2:
                status = False
                print("Length value '{}' is not equal to 2".format(item))
                break
        self.telegramm_decode["PACKET"] = sources
        return status

    # Декодирование заголовка пакета приказа
    def check_header_packet(self):
        """ Decoding the packet header\
        and writing data to a dictionary.\n
        check_header_packet()\n
        ARG: String of bytes in hex.
        """

        status = True
        sources = self.telegramm

        # Проверка, сохранение ID отправителя
        tmp = int(sources[self.desc_header_packet["ID_SOURCE_IND"]], 16)
        if tmp > 1:
            print("Error!  ID_SOURCE = '{}' should be between 0 or 1".format(tmp))
            status = False
        else:
            # self.telegramm_decode["ID_SOURCE"] = self.desc_header_packet["ID"][str(tmp)]
            self.telegramm_decode["ID_SOURCE"] = tmp
        # Проверка, сохранение ID получателя
        tmp = int(sources[self.desc_header_packet["ID_DEST_IND"]], 16)
        if tmp > 1:
            print("Error!  ID_DEST = '{}' should be between 0 or 1".format(tmp))
            status = False
        else:
            # self.telegramm_decode["ID_DEST"] = self.desc_header_packet["ID"][str(tmp)]
            self.telegramm_decode["ID_DEST"] = tmp

        # Проверка, сохранение типа пакета
        tmp = int(sources[self.desc_header_packet["TYPE_PACKET_IND"]], 16)
        key_stat = False
        type_id = self.desc_header_packet["TYPE_ID"]
        for key, val in type_id.items():
            if int(key) == tmp:
                self.telegramm_decode["TYPE_PACKET"] = key
                key_stat = True
                break
        if not key_stat:
            print("Value '{}' out of range type telegramm".format(tmp))
            status = False

        # Проверка, сохранение соответствия указанной длинны пакета
        tmp = int(''.join(sources[self.desc_header_packet["START_DATA_IND"]:self.desc_header_packet["END_DATA_IND"] + 1]), 16)
        if tmp != len(sources):
            print("Error Checking length packet!!! data length = '{0}', actual length = '{1}'".format(tmp, len(sources)))
            status = False
        else:
            self.telegramm_decode["LENGTH_PACKET"] = tmp
        # Проверка на максимально допустимое значение длинны пакета приказа
        tmp = int(''.join(sources[self.desc_header_packet["START_SIZE_AB_IND"]:self.desc_header_packet["END_SIZE_AB_IND"]]), 16)
        if tmp > 4096:
            print("Too long data > 4096 bytes - '{}'".format(tmp))
            status = False
        # Проверка NULL байта
        tmp = int(sources[self.desc_header_packet["NUL_BYTE_IND"]])
        if tmp != 0:
            print("Invalid header structure, Zero byte value = '{}', must be 0".format(tmp))
            status = False
        return status

    # Чтение и проверка согласованности счётчиков A/B пакета приказа
    def _check_count_ab_packet(self):
        """ Reading and checking the consistency\
        of counters A / B order package\n
        check_count_ab_packet()\n
        ARG: String of bytes in hex.
        """

        ct_A = self.telegramm_decode["PACKET_COUNT_A"]
        if ct_A == 0 or ct_A == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_A))
            return False
        ct_B = self.telegramm_decode["PACKET_COUNT_B"]
        if ct_B == 0 or ct_B == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_B))
            return False
        ct_a = self.telegramm_decode["TLG_A"]["COUNT"]
        if ct_a == 0 or ct_a == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_a))
            return False
        ct_b = self.telegramm_decode["TLG_B"]["COUNT"]
        if ct_b == 0 or ct_b == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_b))
            return False
        if ct_A + ct_B == 255:
            if ct_a + ct_b == 255:
                if ct_A - ct_a == 0 and ct_B - ct_b == 0:
                    return True
                else:
                    print("Sum values count packet and count telegramm are not equal")
            else:
                if ct_A - ct_a == 0:
                    print("Error_ctb")
                    return False
                else:
                    print("Error_cta")
                    return False
        else:
            if ct_A - ct_a == 0:
                print("Error_ctb_gl")
                return False
            else:
                print("Error_cta_gl")
                return False

    # Проверка длинны блока телеграмм A/B
    def check_body_telegramm_ab(self):
        """ Check the length of the block of telegrams A / B\n
        check_telegramm_ab("00, ff")\n
        ARG: String of bytes in hex.
        """
        sources = self.telegramm
        # Читаем байт с длинной телеграммы A/B
        size_ab = int(''.join(sources[self.desc_header_packet["START_SIZE_AB_IND"]:self.desc_header_packet["END_SIZE_AB_IND"]]), 16)
        if size_ab == 0:
            print("Empty data A/B - '{}'".format(size_ab))
            return False
        # сохраняем размер телеграммы
        len_tlg_ab = self.telegramm_decode["LENGTH_PACKET"] - 14
        if not len_tlg_ab == size_ab:
            print("Error len A/B")
            return False
        self.telegramm_decode["SIZE_AB"] = size_ab
        start_ab = self.desc_header_packet["END_SIZE_AB_IND"]
        end_ab = size_ab + start_ab
        tlg_ab = sources[start_ab:end_ab]
        if not size_ab == len(tlg_ab):
            print("packet length '{0}' is not equal to the value size A/B '{}'".format(len(tlg_ab), size_ab))
            return False
        else:
            self.telegramm_decode["TELEGRAMM_AB"] = tlg_ab
            #len_tlg_ab = self.telegramm_decode["LENGTH_PACKET"] - 14
            if size_ab == len_tlg_ab:
                return True
            else:
                print("packet length '{0}' is not equal to the value size A/B '{}'".format(len_tlg_ab, size_ab))
            return False

    # Проверка контрольной суммы пакета CRC-16
    def _check_rc_16(self):
        """ checksum packet CRC-16\n
        _check_rc_16("00, ff")\n
        ARG: String of bytes in hex.
        """
        sources = self.telegramm

        r_c = ''.join(sources[len(sources)-2:])
        self.telegramm_decode["RC"] = r_c
        body_packet = bytearray.fromhex(''.join(sources[:len(sources)-2]))
        get_check_rc = Crc16CcittFalse.calchex(body_packet)
        if r_c == get_check_rc.upper():
            return True
        else:
            print("Wrong checksum CRC-16 !!!")
            return False

    # битовый сдвиг вправо
    def _bit_shift_right(self, string_byte):
        tmp = int(string_byte, 16)
        return tmp >> 1

    # Делает инверсию бит в байте. На вход получает список
    def _inversion_byte(self, hex_list):
        tmp = []
        for item in hex_list:
            str_up = "{:02x}".format(int(item, 16).__xor__(255))
            tmp.append(str_up.upper())
        return tmp

    def decode_telegram(self, dsc_tel, telegramm_dec, type=None):
        """
        type = TLG_A or TLG_B
        """
        _dsc_tlg = dsc_tel["TLG_AB"]
        telegramm = telegramm_dec[type]["BODY_TLG"]
        # Читаем общий адрес ОК
        _ok = ''.join(telegramm[_dsc_tlg["OK_START"]:_dsc_tlg["OK_END"]+1])
        # Запишем общий адрес ОК
        telegramm_dec[type]["ADDR_OK"] = _ok
        # Читаем и запишем loop - петля
        telegramm_dec[type]["LOOP_OK"] = _ok[0]
        # Читаем и запишем area - область
        telegramm_dec[type]["AREA_OK"] = self._bit_shift_right(_ok[1])
        # Читаем и запишем hub - концентратор
        telegramm_dec[type]["HUB_OK"] = _ok[2]
        # Читаем и запишем number_ok - номер ОК
        telegramm_dec[type]["NUMBER_OK"] = self._bit_shift_right(_ok[3])
        # Читаем и запишем ML/CO
        telegramm_dec[type]["ML_CO"] = telegramm[_dsc_tlg["ML_CO"]]
        # Читаем и запишем длинну телеграммы
        telegramm_dec[type]["SIZE"] = int(telegramm_dec[type]["ML_CO"][0], 16)
        # Читаем и запишем тип телеграммы
        telegramm_dec[type]["type_co"] = int(telegramm_dec[type]["ML_CO"][1], 16)
        # Читаем и запишем счетчик телеграммы
        telegramm_dec[type]["COUNT"] = int(telegramm[_dsc_tlg["COUNT_AB"]], 16)
        # Читаем и запишем блок DATA
        telegramm_dec[type]["DATA"] = telegramm[_dsc_tlg["COUNT_AB"]+1:telegramm_dec[type]["SIZE"]-1]
        # Читаем и запишем контрольную сумму
        telegramm_dec[type]["RC"] = telegramm[telegramm_dec[type]["SIZE"]-1]
        # Проверка CRC8
        block_crc = str(telegramm_dec[type]["ADDR_OK"]) + \
            str(telegramm_dec[type]["ML_CO"]) + \
            str(''.join(self.telegramm_decode[type]["DATA"]))
        if not telegramm_dec[type]["RC"] == crc8(block_crc):
            #print("Wrong checksum CRC-8 !!!")
            return False
        else:
            return True

    # Декодируем блок DATA
    def decode_zone_status(self, data_list):
        status_zone = {}
        zon = data_list[::-1]
        try:
            key_zone_ = 1
            for zone in zon:
                bin_zones = "{:08b}".format(int(zone, 16))
                zon_offset = -2
                zon_offset_str = 8
                print("")
                for key in range(0, 4):
                    status_zone[key_zone_+key] = int(bin_zones[zon_offset:zon_offset_str], 2)
                    print("Zona_{} = {}".format(
                        key_zone_ + key, int(bin_zones[zon_offset:zon_offset_str], 2)))
                    zon_offset += -2
                    zon_offset_str -= 2
                key_zone_ += key + 1
            self.telegramm_decode["STATUS_ZONE"] = status_zone
            return True
        except:
            print("Error decode block DATA")
            return False

    def _check_id_packet(self):
        type_packet = self.telegramm_decode["TYPE_PACKET"]  # ID отправителя
        source_id = self.telegramm_decode["ID_SOURCE"]
        dest_id = self.telegramm_decode["ID_DEST"]
        # Если ID источника и ID получателя равны
        if source_id == dest_id:
            # Если тип передачи IPU_GATE_RF => EHA
            if type_packet == 2 or type_packet == 4 or type_packet == 5:
                if source_id == 0:
                    print("Error ID resive.")
                    return False
                else:
                    print("Error ID Send.")
                    return False
        else:
            return True

    def _check_type_packet(self):
        type_packet = self.telegramm_decode["TYPE_PACKET"]  # ID отправителя
        source_id = self.telegramm_decode["ID_SOURCE"]
        dest_id = self.telegramm_decode["ID_DEST"]
        if source_id == 0 and dest_id == 1 and type_packet == 3 or\
           source_id == 0 and dest_id == 1 and type_packet == 6 or\
           source_id == 1 and dest_id == 0 and type_packet == 2 or\
           source_id == 1 and dest_id == 0 and type_packet == 4 or\
           source_id == 1 and dest_id == 0 and type_packet == 6:
                print("Error TYPE_ID")
                return False
        else:
            return True

    # Декодируем тело пакета - телеграммы A/B
    def check_decode_ab(self):
        # Описание байтов телеграммы A/B

        _desc_tlg = self.desc_header_packet["TLG_AB"]
        # Тело пакета телеграмм A/B
        _telegramm_ab = self.telegramm_decode["TELEGRAMM_AB"]
        # Определяем тип телеграмм
        mlco = _telegramm_ab[_desc_tlg["ML_CO"]]
        type_co = int(mlco[1], 16)
        type_packet = self.telegramm_decode["TYPE_PACKET"]  # ID отправителя
        source_id = self.telegramm_decode["ID_SOURCE"]
        dest_id = self.telegramm_decode["ID_DEST"]
        # Проверка направления
        # Если это приказ

        if (type_packet == 2 and type_co == 4 or type_packet == 2 and type_co == 6):
            if source_id != 0:
                print("Error ID Send.")
                return False
            if dest_id == 0:
                print("Error ID Resive.")
                return False
            if type_co == 6:  # Если первым пришёл приказ, телеграмма B
                print("There is no telegram A")
                return False
            elif type_co == 4:  # Приказ, телеграмма A
                self.telegramm_decode["TLG_A"]["ML_CO"] = _telegramm_ab[_desc_tlg["ML_CO"]]
                # Вычисляем размер телеграммы А
                self.telegramm_decode["TLG_A"]["SIZE"] = int(self.telegramm_decode["TLG_A"]["ML_CO"][0], 16)
                # Вычисляем блок телеграммы A
                self.telegramm_decode["TLG_A"]["BODY_TLG"] = _telegramm_ab[:self.telegramm_decode["TLG_A"]["SIZE"]]
                # Вычисляем блок телеграммы B
                self.telegramm_decode["TLG_B"]["BODY_TLG"] = _telegramm_ab[self.telegramm_decode["TLG_A"]["SIZE"]:]

                # Сравниваем телеграм A и B по длинне
                len_a = len(self.telegramm_decode["TLG_A"]["BODY_TLG"])
                len_b = len(self.telegramm_decode["TLG_B"]["BODY_TLG"])
                # Если нет телеграммы B
                if len_b == 0:
                    print("There is no telegram B")
                    return False
                # Если размер телеграмм не совпадает
                if not len_a == len_b:
                    # Пишем ошибку
                    print("The length telegramm A({0}) - is not equal to the length telegramm B({1})".format(len_a, len_b))
                    # Прерываем работу
                    return False
                else:
                    # Обработка телеграммы А. Проверка CRC
                    crc_a_status = self.decode_telegram(self.desc_header_packet, self.telegramm_decode, "TLG_A")
                    crc_b_status = self.decode_telegram(self.desc_header_packet, self.telegramm_decode, "TLG_B")
                    if not crc_a_status and not crc_b_status:
                        print("Wrong checksum CRC-8 of the telegramms A and B!!!")
                        return False
                    if not crc_a_status:
                        print("Wrong checksum CRC-8 of the telegramm A!!!")
                        return False
                        # Обработка телеграммы B. Проверка CRC
                    if not crc_b_status:
                        print("Wrong checksum CRC-8 of the telegramm B!!!")
                        return False
                        # Проверка идентичности телеграмм A/B
                    if not self.telegramm_decode["TLG_A"]["DATA"] == self._inversion_byte(self.telegramm_decode["TLG_B"]["DATA"]):
                        print("The data telegramm A is not equal to the data telegramm B")
                        return False
                    else:
                        self.telegramm_decode["PACKET_COUNT_A"] = int(self.telegramm[self.desc_header_packet["PACKET_COUNT_A_IND"]], 16)
                        self.telegramm_decode["PACKET_COUNT_B"] = int(self.telegramm[self.desc_header_packet["PACKET_COUNT_B_IND"]], 16)
                        ## Проверка счётчиков телеграмм A/B
                        #count_ab = self.telegramm_decode["TLG_A"]["COUNT"] + self.telegramm_decode["TLG_B"]["COUNT"]
                        #if not count_ab == 255:
                        #    print("The sum of the values count A/B of telegramm A/B '{}'\
                        #    is not equal to the value '255'".format(count_ab))
                        #    return False
                        #else:
                        # if not self.decode_zone_status(self.telegramm_decode["TLG_A"]["DATA"]):
                        #     print("Wrong decode block Data")
                        #     return False
                        # else:
                        return True

        #  Если это передача статусов
        if (type_packet == 3 and type_co == 8 or type_packet == 3 and type_co == 8):
            print("This send status")
        else:
            print("Error checking  type CO of telegramm. CO = '{}, TYPE_PACKET = '{}'".format(type_co, type_packet))
            return False

    def check_global_count_order(self):
        """ Reading and checking the consistency\
        of counters A / B order package\n
        check_count_ab_packet()\n
        ARG: String of bytes in hex.
        """

        ct_A = self.telegramm_decode["PACKET_COUNT_A"]
        if ct_A == 0 or ct_A == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_A))
            return False
        ct_B = self.telegramm_decode["PACKET_COUNT_B"]
        if ct_B == 0 or ct_B == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_B))
            return False
        ct_a = self.telegramm_decode["TLG_A"]["COUNT"]
        if ct_a == 0 or ct_a == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_a))
            return False
        ct_b = self.telegramm_decode["TLG_B"]["COUNT"]
        if ct_b == 0 or ct_b == 255:
            print("The value can not be 0 or 255: '{}'".format(ct_b))
            return False
        if ct_A + ct_B == 255:
            if ct_a + ct_b == 255:
                if ct_A - ct_a == 0 and ct_B - ct_b == 0:
                    return True
                else:
                    print("Sum values count packet and count telegramm are not equal")
            else:
                if ct_A - ct_a == 0:
                    print("Error_ctb")
                    return False
                else:
                    print("Error_cta")
                    return False
        else:
            if ct_A - ct_a == 0:
                print("Error_ctb_gl")
                return False
            else:
                print("Error_cta_gl")
                return False

        ## Проверка счётчиков телеграмм A/B
        #if self.telegramm_decode["TLG_A"]["COUNT"] == self.telegramm_decode["PACKET_COUNT_A"] and\
        # self.telegramm_decode["TLG_B"]["COUNT"] == self.telegramm_decode["PACKET_COUNT_B"]:
        #    return True
        #else:
        #    print("Summ Count A/B of packet is not equal to the summ count telegramm A/B")
        #    return False

    # Проверка правильности принятой телеграммы
    def check_telegramm(self):
        if not self._check_rc_16() or not\
                self.check_header_packet() or not\
                self.check_body_telegramm_ab() or not\
                self._check_id_packet() or not\
                self._check_type_packet() or not\
                self.check_decode_ab() or not\
                self.check_global_count_order() or not\
                self.decode_zone_status(''.join(self.telegramm_decode['TLG_A']['DATA'])):
            return False
        else:
            return True
