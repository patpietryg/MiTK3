import unittest
from unittest.mock import patch
from main import PasswordManager

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.password_manager = PasswordManager(':memory:')  # Using an in-memory database for testing

    def test_add_user_valid(self):
        # Valid username, password, and confirmation
        with patch('builtins.input', side_effect=['new_user', 'password123!', 'password123!']):
            result = self.password_manager.add_user('new_user', 'password123!', 'password123!')
        self.assertTrue(result)

    def test_add_user_invalid_username(self):
        # Invalid username
        with patch('builtins.input', side_effect=['', 'password123!', 'password123!']):
            result = self.password_manager.add_user('', 'password123!', 'password123!')
        self.assertFalse(result)

    def test_add_user_invalid_password_length(self):
        # Password length less than 8
        with patch('builtins.input', side_effect=['new_user', 'pass', 'pass']):
            result = self.password_manager.add_user('new_user', 'pass', 'pass')
        self.assertFalse(result)

    def test_add_user_invalid_password_characters(self):
        # Password without special characters
        with patch('builtins.input', side_effect=['new_user', 'password', 'password']):
            result = self.password_manager.add_user('new_user', 'password', 'password')
        self.assertFalse(result)

    def test_add_user_password_mismatch(self):
        # Passwords don't match
        with patch('builtins.input', side_effect=['new_user', 'password123!', 'password']):
            result = self.password_manager.add_user('new_user', 'password123!', 'password')
        self.assertFalse(result)

    def test_add_user_existing_username(self):
        # Username already exists in the database
        self.password_manager.add_password('existing_user', 'password123!')
        with patch('builtins.input', side_effect=['existing_user', 'password123!', 'password123!']):
            result = self.password_manager.add_user('existing_user', 'password123!', 'password123!')
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()