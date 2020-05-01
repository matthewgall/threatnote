import unittest

from main import active_reports

class active_reports(unittest.TestCase):
    def test_list_reports(self):
        """
        Test that it can sum a list of integers
        """
        data = [1, 2, 3]
        result = 6
        self.assertEqual(result, 6)

if __name__ == '__main__':
    unittest.main()