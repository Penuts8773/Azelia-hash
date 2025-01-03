from flask_mysqldb import MySQL
from azelia.azelia import PasswordHashGen
from azelia.config import Config

class PasswordManager:
    def __init__(self, mysql: MySQL, work_factor: int = 15):
        self.__mysql = mysql
        self.__hasher = PasswordHashGen(work_factor)
        self.__table_name = Config.USER_TABLE_NAME  # Use the table name from the config

    def __hash_password(self, password: str) -> tuple[str, str]:
        return self.__hasher.generate_hash(password)

    def __verify_password(self, plain_password: str, hashed_password: str, stored_pepper: str) -> bool:
        return self.__hasher.verify_hash(plain_password, hashed_password, stored_pepper)

    def __insert_user_to_db(self, username: str, hashed_password: str, pepper: str) -> bool:
        cur = self.__mysql.connection.cursor()
        # Use the table name dynamically here
        cur.execute(f"SELECT * FROM {self.__table_name} WHERE username = %s", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            return False  # User already exists

        cur.execute(
            f"INSERT INTO {self.__table_name} (username, password, pepper) VALUES (%s, %s, %s)",
            (username, hashed_password, pepper)
        )
        self.__mysql.connection.commit()
        cur.close()
        return True

    def create_user(self, username: str, password: str) -> tuple[bool, list]:
        hashed_password, pepper = self.__hash_password(password)

        # Insert user into database
        if not self.__insert_user_to_db(username, hashed_password, pepper):
            return False, ["Username already taken"]
        
        return True, ["Account successfully created! Please log in."]
    
    def authenticate_user(self, username: str, plain_password: str) -> tuple[bool, list]:
        cur = self.__mysql.connection.cursor()
        # Use the table name dynamically here
        cur.execute(f"SELECT password, pepper FROM {self.__table_name} WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if not user:
            return False, ["Username not found"]

        hashed_password, stored_pepper = user
        if not self.__verify_password(plain_password, hashed_password, stored_pepper):
            return False, ["Incorrect password"]

        return True, []
