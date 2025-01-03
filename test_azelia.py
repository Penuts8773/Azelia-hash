import unittest
from unittest.mock import MagicMock
from azelia.password_handler import PasswordManager
from azelia.password_policies import PasswordPolicies
from azelia.azelia import PasswordHashGen
from mysql.connector import connect

class TestPasswordManager(unittest.TestCase):

    def setUp(self):
        self.mock_connection = MagicMock()
        self.password_manager = PasswordManager(connection=self.mock_connection)
        self.password_policies = PasswordPolicies()
        self.password_hash_gen = PasswordHashGen()

    def test_create_user_success(self):
        """Test creating a user successfully."""
        self.mock_connection.cursor().fetchone.return_value = None
        self.mock_connection.cursor().execute.return_value = None
        self.mock_connection.commit.return_value = None

        result, messages = self.password_manager.create_user("testuser", "StrongPass1!")
        print("Function: test_create_user_success")
        print("Result:", result)
        print("Expected: True")
        print("Messages:", messages)
        print("Expected Messages: [\"Account successfully created! Please log in.\"]\n")
        self.assertTrue(result)
        self.assertEqual(messages, ["Account successfully created! Please log in."])

    def test_create_user_already_exists(self):
        """Test creating a user that already exists."""
        self.mock_connection.cursor().fetchone.return_value = ("testuser",)

        result, messages = self.password_manager.create_user("testuser", "StrongPass1!")
        print("Function: test_create_user_already_exists")
        print("Result:", result)
        print("Expected: False")
        print("Messages:", messages)
        print("Expected Messages: [\"Username already taken\"]\n")
        self.assertFalse(result)
        self.assertEqual(messages, ["Username already taken"])

    def test_authenticate_user_success(self):
        """Test authenticating a user successfully."""
        self.mock_connection.cursor().fetchone.return_value = ("bcrypt_hashed_password", "argon2_pepper")
        self.password_manager._PasswordManager__hasher.verify_hash = MagicMock(return_value=True)

        result, messages = self.password_manager.authenticate_user("testuser", "StrongPass1!")
        print("Function: test_authenticate_user_success")
        print("Result:", result)
        print("Expected: True")
        print("Messages:", messages)
        print("Expected Messages: []\n")
        self.assertTrue(result)
        self.assertEqual(messages, [])

    def test_authenticate_user_wrong_password(self):
        """Test authenticating a user with the wrong password."""
        self.mock_connection.cursor().fetchone.return_value = ("bcrypt_hashed_password", "argon2_pepper")
        self.password_manager._PasswordManager__hasher.verify_hash = MagicMock(return_value=False)

        result, messages = self.password_manager.authenticate_user("testuser", "WrongPass")
        print("Function: test_authenticate_user_wrong_password")
        print("Result:", result)
        print("Expected: False")
        print("Messages:", messages)
        print("Expected Messages: [\"Incorrect password\"]\n")
        self.assertFalse(result)
        self.assertEqual(messages, ["Incorrect password"])

    def test_authenticate_user_not_found(self):
        """Test authenticating a user that does not exist."""
        self.mock_connection.cursor().fetchone.return_value = None

        result, messages = self.password_manager.authenticate_user("nonexistentuser", "StrongPass1!")
        print("Function: test_authenticate_user_not_found")
        print("Result:", result)
        print("Expected: False")
        print("Messages:", messages)
        print("Expected Messages: [\"Username not found\"]\n")
        self.assertFalse(result)
        self.assertEqual(messages, ["Username not found"])

    def test_check_password_strength_success(self):
        """Test password strength with a valid password."""
        result, errors = self.password_policies.check_password_strength("StrongPass1!")
        print("Function: test_check_password_strength_success")
        print("Result:", result)
        print("Expected: True")
        print("Errors:", errors)
        print("Expected Errors: []\n")
        self.assertTrue(result)
        self.assertEqual(errors, [])

    def test_check_password_strength_failure(self):
        """Test password strength with an invalid password."""
        result, errors = self.password_policies.check_password_strength("weak")
        print("Function: test_check_password_strength_failure")
        print("Result:", result)
        print("Expected: False")
        print("Errors:", errors)
        print("Expected Errors: [\"Password must be at least 8 characters long.\", \"Password must contain at least 1 uppercase letter(s).\", \"Password must contain at least 1 digit(s).\", \"Password must contain at least 1 special character(s).\"]\n")
        self.assertFalse(result)
        self.assertIn("Password must be at least 8 characters long.", errors)
        self.assertIn("Password must contain at least 1 uppercase letter(s).", errors)
        self.assertIn("Password must contain at least 1 digit(s).", errors)
        self.assertIn("Password must contain at least 1 special character(s).", errors)

    def test_generate_hash_and_verify(self):
        """Test PasswordHashGen generate_hash and verify_hash methods."""
        password = "StrongPass1!"
        hashed_password, pepper = self.password_hash_gen.generate_hash(password)
        result = self.password_hash_gen.verify_hash(password, hashed_password, pepper)

        print("Function: test_generate_hash_and_verify")
        print("Generated Hash:", hashed_password)
        print("Generated Pepper:", pepper)
        print("Verification Result:", result)
        print("Expected: True\n")

        self.assertTrue(result)

if __name__ == "__main__":
    unittest.main()
