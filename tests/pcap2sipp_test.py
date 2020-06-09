'''
Created on 5 giu 2020

@author: augello
'''
import unittest
from context import pcap2sipp

try:
    # python 3.4+ should use builtin unittest.mock not mock package
    from unittest.mock import patch
except ImportError:
    from mock import patch
    
class Test(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testName_noArgs(self):
        with self.assertRaises(SystemExit) as se:
            pcap2sipp.handleArguments()
        self.assertEqual(se.exception.code, 2)
    
    def testName_incompleteArgs(self):
        testargs = ["pcap2sipp", "pippo.pcap", "/tmp"]
        with patch('sys.argv', testargs):
            with self.assertRaises(SystemExit) as se:
                pcap2sipp.handleArguments()
        self.assertEqual(se.exception.code, 2)
    
    def testName_completeArgs(self):
        testargs = ["pcap2sipp", "pippo.pcap", "/tmp", "138.132.1.1", "1.1.1.1"]
        with patch('sys.argv', testargs):
            try:
                pcap2sipp.handleArguments()
            except:
                pytest.fail("no exception expected")
                pcap2sipp.handleArguments()

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()