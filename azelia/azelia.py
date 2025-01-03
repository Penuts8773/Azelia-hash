from azelia.azeliaconfig import AzeliaConfig
from argon2 import PasswordHasher
import bcrypt

class PasswordHashGen:
    def __init__(self):
        self.__work_factor = AzeliaConfig.BCRYPT_WORK_FACTOR
        self.__argon2 = PasswordHasher(
            time_cost=AzeliaConfig.ARGON2_TIME_COST,
            memory_cost=AzeliaConfig.ARGON2_MEMORY_COST,
            parallelism=AzeliaConfig.ARGON2_PARALLELISM,
            hash_len=AzeliaConfig.ARGON2_HASH_LENGTH,
            salt_len=AzeliaConfig.ARGON2_SALTSIZE,
        )

    def generate_hash(self, password: str) -> tuple[str, str]:
        """
        Generate a hashed password using Argon2 as a pepper and bcrypt for final hashing.
        Returns the bcrypt hash and Argon2 pepper.
        """
        argon2_pepper = self.__argon2.hash(password)
        password_with_pepper = password + argon2_pepper
        salt = bcrypt.gensalt(rounds=self.__work_factor)
        hashed = bcrypt.hashpw(password_with_pepper.encode('utf-8'), salt)
        return hashed.decode('utf-8'), argon2_pepper

    def verify_hash(self, plain_password: str, hashed_password: str, stored_pepper: str) -> bool:
        """
        Verify a plain password against a bcrypt hash and stored Argon2 pepper.
        """
        try:
            password_with_pepper = plain_password + stored_pepper
            return bcrypt.checkpw(password_with_pepper.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception:
            return False
