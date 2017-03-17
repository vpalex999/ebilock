import unittest
import sources.ebilockcmain as ebm

TEST_OK = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 FB 18 4F 4C EE"
ERR_CTA = "00 01 02 00 00 00 1A 00 03 FC 00 0C 72 07 64 EF E7 69 72 07 66 FC 18 4F 9A 5A"
ERR_CTB = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 0F 18 4F 73 7C"
ERR_CTAB = "00 01 02 00 00 00 1A 00 03 FC 00 0C 72 07 64 EF E7 69 72 07 66 10 18 4F 4F 0A"
ERR_CRCA = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 6E 72 07 66 FB 18 4F 55 AA"
ERR_CRCB = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 FB 18 54 EF B4"
ERR_CRCAB = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 6E 72 07 66 FB 18 54 F6 F0"
ERR_NOT_A = "00 01 02 00 00 00 14 00 03 FC 00 06 72 07 66 FC 18 4F EC B6"
ERR_NOT_B = "00 01 02 00 00 00 14 00 03 FC 00 06 72 07 64 03 E7 69 89 E6"
ERR_CONC = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 FB E7 C2 0F 34"
ERR_CO = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 68 04 E7 99 72 07 6C FB 18 C7 FC 23"
ERR_CRC16 = "00 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 FB 18 4F 4C F1"
ERR_SEND = "01 01 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 FB 18 4F 7B ED"
ERR_RECV = "00 00 02 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 FB 18 4F 29 E5"
ERR_LEN = "00 01 02 00 00 00 1F 00 03 FC 00 0C 72 07 64 03 E7 69 72 07 66 FC 18 4F 68 4B"
ERR_TYPE = "00 01 03 00 00 00 1A 00 04 FB 00 0C 72 07 64 04 E7 69 72 07 66 FB 18 4F 21 36"
ERR_ZERO = "00 01 02 00 00 00 1A 01 03 FC 00 0C 72 07 64 03 E7 69 72 07 66 FC 18 4F 78 3F"
ERR_CTA_GL = "00 01 02 00 00 00 1A 00 F1 FA 00 0C 72 07 64 05 E7 69 72 07 66 FA 18 4F F7 B0"
ERR_CTB_GL = "00 01 02 00 00 00 1A 00 04 0F 00 0C 72 07 64 04 E7 69 72 07 66 FB 18 4F 7A D9"
ERR_CTAB_GL = "00 01 02 00 00 00 1A 00 EF 10 00 0C 72 07 64 03 E7 69 72 07 66 FC 18 4F 64 3F"
ERR_LEN_AB = "00 01 02 00 00 00 1A 00 03 FC 00 73 72 07 64 03 E7 69 72 07 66 FC 18 4F C8 83"
ERR_LEN_OC = "00 01 02 00 00 00 1A 00 02 FD 00 0C 72 07 64 02 E7 69 72 07 66 FD 18 4F B2 16"

class TestTelegramm(unittest.TestCase):
    """ Checking Telegramm """

    # def setUp(self):
    #     self.tlg = ebm.Edilock(TEST_ERR_CTA)

    @unittest.skip("")
    def test_check_telegramm_ok(self):
        tlg = ebm.Edilock(TEST_OK)
        self.assertTrue(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_cta(self):
        tlg = ebm.Edilock(ERR_CTA)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_ctb(self):
        tlg = ebm.Edilock(ERR_CTB)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_ctab(self):
        tlg = ebm.Edilock(ERR_CTAB)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_crca(self):
        tlg = ebm.Edilock(ERR_CRCA)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_crcb(self):
        tlg = ebm.Edilock(ERR_CRCB)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_crcab(self):
        tlg = ebm.Edilock(ERR_CRCAB)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_not_a(self):
        tlg = ebm.Edilock(ERR_NOT_A)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_not_b(self):
        tlg = ebm.Edilock(ERR_NOT_B)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_conc(self):
        tlg = ebm.Edilock(ERR_CONC)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_co(self):
        tlg = ebm.Edilock(ERR_CO)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_crc16(self):
        tlg = ebm.Edilock(ERR_CRC16)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_send(self):
        tlg = ebm.Edilock(ERR_SEND)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_recv(self):
        tlg = ebm.Edilock(ERR_RECV)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_len(self):
        tlg = ebm.Edilock(ERR_LEN)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_type(self):
        tlg = ebm.Edilock(ERR_TYPE)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_zero(self):
        tlg = ebm.Edilock(ERR_ZERO)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_cta_gl(self):
        tlg = ebm.Edilock(ERR_CTA_GL)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_ctb_gl(self):
        tlg = ebm.Edilock(ERR_CTB_GL)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_ctab_gl(self):
        tlg = ebm.Edilock(ERR_CTAB_GL)
        self.assertFalse(tlg.check_telegramm())

    @unittest.skip("")
    def test_check_telegramm_err_len_ab(self):
        tlg = ebm.Edilock(ERR_LEN_AB)
        self.assertFalse(tlg.check_telegramm())

    # @unittest.skip("")
    def test_check_telegramm_err_len_oc(self):
        tlg = ebm.Edilock(ERR_LEN_OC)
        self.assertFalse(tlg.check_telegramm())


if __name__ == "__main__":
    unittest.main()
