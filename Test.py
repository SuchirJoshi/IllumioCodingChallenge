import unittest
import Firewall

"""I referred to this link: https://realpython.com/python-testing/, for a quick refresher on
how using the unittest module works. I used it for checking the format of each assertEqual statement,
and making sure that my final if statement was correct."""


class Test(unittest.TestCase):

    def test_given(self):
        fw = Firewall.Firewall("ProvidedTest.csv")

        self.assertEqual(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"), True, "True")
        self.assertEqual(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"), True, "True")
        self.assertEqual(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"), True, "True")
        self.assertEqual(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"), False, "False")
        self.assertEqual(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"), False, "False")

    def test_created(self):
        fw = Firewall.Firewall("MyOwnTest.csv")

        self.assertEqual(fw.accept_packet("inbound", "tcp", 0, "0.0.0.1"), True, "True")
        self.assertEqual(fw.accept_packet("inbound", "udp", 1, "0.0.0.255"), True, "True")
        self.assertEqual(fw.accept_packet("inbound", "tcp", 0, "0.0.0.2"), False, "False")
        self.assertEqual(fw.accept_packet("outbound", "udp", 5, "0.0.0.0"), True, "True")

if __name__ == '__main__':
    unittest.main()
