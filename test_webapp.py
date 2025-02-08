import unittest
from unittest.mock import MagicMock, patch
from webapp import safe_db_operation, db

class TestSafeDbOperation(unittest.TestCase):

    @patch('webapp.db')
    def test_db_not_connected(self, mock_db):
        mock_db = None
        result, error = safe_db_operation(lambda: "test")
        self.assertIsNone(result)
        self.assertEqual(error, "Database not connected")

    @patch('webapp.db')
    def test_successful_operation(self, mock_db):
        mock_db = MagicMock()
        operation = MagicMock(return_value="success")
        result, error = safe_db_operation(operation)
        self.assertEqual(result, "success")
        self.assertIsNone(error)

    @patch('webapp.db')
    def test_operation_exception(self, mock_db):
        mock_db = MagicMock()
        operation = MagicMock(side_effect=Exception("Test exception"))
        result, error = safe_db_operation(operation)
        self.assertIsNone(result)
        self.assertEqual(error, "Test exception")

if __name__ == '__main__':
    unittest.main()