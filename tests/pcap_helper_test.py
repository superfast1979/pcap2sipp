import unittest
from context import pcap_helper
import pytest

class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @pytest.mark.skip(reason="does not run on linux")
    def test_parsePcap_typical(self):
        pcap_helper.parsePcap("./example.pcap")
            
if __name__ == "__main__":
    unittest.main()