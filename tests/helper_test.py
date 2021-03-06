'''
Created on 5 giu 2020

@author: augello
'''
import unittest
from context import helper
import pytest

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

    def test_handleArguments_no_args(self):
        with self.assertRaises(SystemExit) as se:
            helper.handleArguments()
        self.assertEqual(se.exception.code, 2)
    
    def test_handleArguments_incomplete_args(self):
        testargs = ["pcap2sipp", "pippo.pcap", "/tmp"]
        with patch('sys.argv', testargs):
            with self.assertRaises(SystemExit) as se:
                helper.handleArguments()
        self.assertEqual(se.exception.code, 2)
    
    def test_handleArguments_complete_args(self):
        testargs = ["pcap2sipp", "pippo.pcap", "/tmp", "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186"]
        with patch('sys.argv', testargs):
            try:
                args = helper.handleArguments()
            except:
                pytest.fail("no exception expected")
        self.assertEqual(args.pcap, "pippo.pcap")
        self.assertEqual(args.path, "/tmp")
        self.assertEqual(args.callid, "g000000q5m2003tedhjqk9l5i1-jbe0000@10.252.47.186")
    
    @patch('os.path.isfile')
    def test_checkPcap_pcap_not_found(self, mock_os_is_file):
        mock_os_is_file.return_value =  False
        with self.assertRaises(Exception) as e:
            helper.checkPcap('./file_not_found.pcap')
        self.assertEqual(str(e.exception), "pcap not found")
        
    @patch('os.path.isdir')
    def test_checkPath_path_is_not_dir(self, mock_os_is_dir):
        mock_os_is_dir.return_value = False
        with self.assertRaises(Exception) as e:
            helper.checkPath('/tmsrsc/')
        self.assertEqual(str(e.exception), "path not found")

#     def test_checkIp_client_is_not_valid_ipv4(self):
#         with self.assertRaises(Exception) as e:
#             helper.checkIp("1.0.1.2.3")
#         self.assertEqual(str(e.exception), "1.0.1.2.3 not a valid ip")
# 
#     def test_checkIp_server_is_not_valid_ipv4(self):
#         with self.assertRaises(Exception) as e:
#             helper.checkIp("1.0.1.2.4")
#         self.assertEqual(str(e.exception), "1.0.1.2.4 not a valid ip")

    @patch('os.path.isdir')
    @patch('os.path.isfile')
    def test_checkArgs_valid_arguments(self, mock_os_isdir, mock_os_isfile):
        mock_os_isdir.return_value = True
        mock_os_isfile.return_value = True
        
        args = dict()
        args['path'] = './'
        args['pcap'] = './example.pcap'
        args['src'] = '1.1.1.1'
        args['dst'] = '138.132.1.1'
        
        try:
            helper.checkArgs(args)
        except:
            self.fail("no exception expected")

if __name__ == "__main__":
    unittest.main()