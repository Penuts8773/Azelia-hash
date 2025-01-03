from azelia.azeliaconfig import AzeliaConfig
from argon2 import PasswordHasher
import bcrypt

class PasswordHashGen:
    def __init__(
        self,
        work_factor: int = AzeliaConfig.BCRYPT_WORK_FACTOR,
        time_cost: int = AzeliaConfig.ARGON2_TIME_COST,
        memory_cost: int = AzeliaConfig.ARGON2_MEMORY_COST,
        parallelism: int = AzeliaConfig.ARGON2_PARALLELISM,
        hash_length: int = AzeliaConfig.ARGON2_HASH_LENGTH,
        salt_size: int = AzeliaConfig.ARGON2_SALTSIZE,
    ):
        self.__work_factor = work_factor
        self.__argon2 = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_length,
            salt_len=salt_size,
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
