import unittest
import ebilock as eb

TEST_TELEGRAMM = "00 01 02 00 00 00 1A 00 03 FC 00 0C 72 07 64 03 80 3D 72 07 66 FC 7F 1B 81 E0"


class TestTelegramm(unittest.TestCase):
    """ Checking Telegramm """

    @unittest.skip("")
    def test_telegramm(self):
        """ Test telegramm """
        eb.read_telegramm(TEST_TELEGRAMM)
        pass

    @unittest.skip("")
    def test_check_telegramm_flow(self):
        self.assertTrue(eb.check_byte_flow(TEST_TELEGRAMM))

    @unittest.skip("")
    def test_check_header_packet(self):
        self.assertTrue(eb.check_header_packet(TEST_TELEGRAMM), "Invalid header structure!!!")

    @unittest.skip("")
    def test_count_ab_from_packet(self):
        self.assertTrue(eb.check_packet_count_ab(TEST_TELEGRAMM), "Invalid count telegramm AB from packet")

    @unittest.skip("")
    def test_size_ab(self):
        self.assertTrue(eb.check_size_ab(TEST_TELEGRAMM), "Invalid size telegramm AB")

    @unittest.skip("")
    def test_get_telegramm_ab(self):
        self.assertTrue(eb.check_byte_flow(TEST_TELEGRAMM))
        self.assertTrue(eb.check_header_packet(TEST_TELEGRAMM), "Invalid header structure!!!")
        self.assertTrue(eb.check_packet_count_ab(TEST_TELEGRAMM), "Invalid count telegramm AB from packet")
        self.assertTrue(eb.check_size_ab(TEST_TELEGRAMM), "Invalid size telegramm AB")
        self.assertTrue(eb.check_telegramm_ab(TEST_TELEGRAMM))

    @unittest.skip("")
    def test_check_packet_rc(self):
        self.assertTrue(eb.check_byte_flow(TEST_TELEGRAMM))
        self.assertTrue(eb.check_header_packet(TEST_TELEGRAMM), "Invalid header structure!!!")
        self.assertTrue(eb.check_packet_count_ab(TEST_TELEGRAMM), "Invalid count telegramm AB from packet")
        self.assertTrue(eb.check_size_ab(TEST_TELEGRAMM), "Invalid size telegramm AB")
        self.assertTrue(eb.check_telegramm_ab(TEST_TELEGRAMM))
        self.assertTrue(eb.check_rc(TEST_TELEGRAMM))

    @unittest.skip("")
    def test_check_telegramm(self):
        self.assertTrue(eb.check_telegramm(TEST_TELEGRAMM))

    def test_decode_ab(self):
        self.assertTrue(eb.check_telegramm(TEST_TELEGRAMM))
        eb.check_decode_ab(TEST_TELEGRAMM)


if __name__ == "__main__":
    unittest.main()
