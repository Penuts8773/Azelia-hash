class AzeliaConfig:
    # Configurations for Password Hashing

    # Bcrypt Configurations
    BCRYPT_WORK_FACTOR = 15  # The work factor for bcrypt, higher is more secure but slower

    # Argon2 Configurations
    ARGON2_TIME_COST = 15  # The time cost for Argon2 (number of iterations)
    ARGON2_MEMORY_COST = 102400  # Memory cost in kibibytes
    ARGON2_PARALLELISM = 8  # Number of threads used by Argon2
    ARGON2_HASH_LENGTH = 32  # Length of the hash produced by Argon2
    ARGON2_SALTSIZE = 16  # Length of the salt for Argon2

    # Configurations for Password Strength Validation
    MIN_PASSWORD_LENGTH = 8  # Minimum length for the password
    REQUIRE_UPPERCASE = 1    # Minimum number of uppercase letters required
    REQUIRE_LOWERCASE = 1    # Minimum number of lowercase letters required
    REQUIRE_NUMERIC = 1      # Minimum number of digits required
    REQUIRE_SPECIAL = 1      # Minimum number of special characters required

    # Define what characters are considered special
    #chotholly nota
    SPECIAL_CHARACTERS = r'[\W_]'  # Any non-alphanumeric character
