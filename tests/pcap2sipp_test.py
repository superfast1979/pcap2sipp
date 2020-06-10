'''
Created on 5 giu 2020

@author: augello
'''
import unittest
import argparse
from context import pcap2sipp

try:
    # python 3.4+ should use builtin unittest.mock not mock package
    from unittest.mock import patch
except ImportError:
    from mock import patch
    
class Test(unittest.TestCase):

    def setUp(self):
        self.args = dict()
        self.args['path'] = './'
        self.args['pcap'] = './example.pcap'
        self.args['src'] = '1.1.1.1'
        self.args['dst'] = '138.132.1.1'

    def tearDown(self):
        pass

    def test_handleArguments_no_args(self):
        with self.assertRaises(SystemExit) as se:
            pcap2sipp.handleArguments()
        self.assertEqual(se.exception.code, 2)
    
    def test_handleArguments_incomplete_args(self):
        testargs = ["pcap2sipp", "pippo.pcap", "/tmp"]
        with patch('sys.argv', testargs):
            with self.assertRaises(SystemExit) as se:
                pcap2sipp.handleArguments()
        self.assertEqual(se.exception.code, 2)
    
    def test_handleArguments_complete_args(self):
        testargs = ["pcap2sipp", "pippo.pcap", "/tmp", "138.132.1.1", "1.1.1.1"]
        with patch('sys.argv', testargs):
            try:
                args = pcap2sipp.handleArguments()
            except:
                pytest.fail("no exception expected")
        self.assertEqual(args.pcap, "pippo.pcap")
        self.assertEqual(args.path, "/tmp")
        self.assertEqual(args.src, "138.132.1.1")
        self.assertEqual(args.dst, "1.1.1.1")
        
    def test_checkArgs_pcap_not_found(self):
        self.args['pcap'] = './file_not_exists.pcap'
        with self.assertRaises(Exception) as e:
            pcap2sipp.checkArgs(self.args)
        self.assertEqual(str(e.exception), "no pcap found")
        
    def test_checkArgs_path_is_not_dir(self):
        self.args['path'] = '/nodirexists/'
        with self.assertRaises(Exception) as e:
            pcap2sipp.checkArgs(self.args)
        self.assertEqual(str(e.exception), "path not found")
        
    def test_checkArgs_src_is_not_valid_ipv4(self):
        self.args['src'] = '1.0.1.2.3'
        with self.assertRaises(ValueError):
            pcap2sipp.checkArgs(self.args)

    def test_checkArgs_dst_is_not_valid_ipv4(self):
        self.args['dst'] = '1.0.1.2.3'
        with self.assertRaises(ValueError):
            pcap2sipp.checkArgs(self.args)
            
    def test_checkArgs_valid_arguments(self):
        try:
            pcap2sipp.checkArgs(self.args)
        except:
            pytest.fail("no exception expected")

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()