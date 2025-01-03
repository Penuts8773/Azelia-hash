import sys
sys.path.append('..')
import unittest
from unittest.mock import patch
from azelia.azelia import PasswordHashGen
from azelia.azeliaconfig import AzeliaConfig

class TestPasswordHashGen(unittest.TestCase):
    
    def setUp(self):
        # Set up the PasswordHashGen instance for testing
        self.password_gen = PasswordHashGen(
            work_factor=AzeliaConfig.BCRYPT_WORK_FACTOR,
            salt_length=AzeliaConfig.BCRYPT_SALT_LENGTH,
            time_cost=AzeliaConfig.ARGON2_TIME_COST,
            memory_cost=AzeliaConfig.ARGON2_MEMORY_COST,
            parallelism=AzeliaConfig.ARGON2_PARALLELISM,
            hash_length=AzeliaConfig.ARGON2_HASH_LENGTH,
            salt_size=AzeliaConfig.ARGON2_SALTSIZE
        )
        self.password = "TestPassword123!"
    
    @patch('argon2.PasswordHasher.hash')
    def test_generate_hash(self, mock_hash):
        # Mock the Argon2 hash result
        mock_hash.return_value = "argon2_pepper_mocked"
        
        # Generate password hash using the instance
        bcrypt_hash, argon2_pepper = self.password_gen.generate_hash(self.password)
        
        # Check the bcrypt hash and Argon2 pepper values
        self.assertIsInstance(bcrypt_hash, str)
        self.assertIsInstance(argon2_pepper, str)
        self.assertEqual(argon2_pepper, "argon2_pepper_mocked")
        self.assertTrue(bcrypt_hash.startswith("$2b$"))  # bcrypt hash starts with "$2b$"

    @patch('argon2.PasswordHasher.verify')
    def test_verify_hash(self, mock_verify):
        # Mock the verification of hash as True
        mock_verify.return_value = True
        
        # Generate a bcrypt hash and Argon2 pepper
        bcrypt_hash, argon2_pepper = self.password_gen.generate_hash(self.password)
        
        # Test password verification
        result = self.password_gen.verify_hash(self.password, bcrypt_hash, argon2_pepper)
        
        # Check if the password is verified correctly
        self.assertTrue(result)
    
    @patch('argon2.PasswordHasher.verify')
    def test_verify_hash_invalid_password(self, mock_verify):
        # Mock the verification of hash as False for incorrect password
        mock_verify.return_value = False
        
        # Generate a bcrypt hash and Argon2 pepper
        bcrypt_hash, argon2_pepper = self.password_gen.generate_hash(self.password)
        
        # Test password verification with an incorrect password
        result = self.password_gen.verify_hash("WrongPassword123!", bcrypt_hash, argon2_pepper)
        
        # Check if the password verification fails
        self.assertFalse(result)

    def test_bcrypt_hash_format(self):
        # Generate password hash and ensure it follows bcrypt format
        bcrypt_hash, _ = self.password_gen.generate_hash(self.password)
        self.assertTrue(bcrypt_hash.startswith("$2b$"))  # bcrypt hash starts with "$2b$"
        self.assertTrue(len(bcrypt_hash) > 50)  # bcrypt hashes are typically long
    
if __name__ == '__main__':
    # Create a test suite and run it using a test runner
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPasswordHashGen)
    runner = unittest.TextTestRunner(verbosity=2)  # Adjust verbosity for detailed output
    runner.run(suite)
