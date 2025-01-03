import re
from azelia.azeliaconfig import AzeliaConfig

class PasswordPolicies:
    def __init__(self):
        pass

    def check_password_strength(self, password: str) -> tuple[bool, list]:
        errors = []
        
        if len(password) < AzeliaConfig.MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {AzeliaConfig.MIN_PASSWORD_LENGTH} characters long.")
        
        if len(re.findall(r'[A-Z]', password)) < AzeliaConfig.REQUIRE_UPPERCASE:
            errors.append(f"Password must contain at least {AzeliaConfig.REQUIRE_UPPERCASE} uppercase letter(s).")
        
        if len(re.findall(r'[a-z]', password)) < AzeliaConfig.REQUIRE_LOWERCASE:
            errors.append(f"Password must contain at least {AzeliaConfig.REQUIRE_LOWERCASE} lowercase letter(s).")
        
        if len(re.findall(r'[0-9]', password)) < AzeliaConfig.REQUIRE_NUMERIC:
            errors.append(f"Password must contain at least {AzeliaConfig.REQUIRE_NUMERIC} digit(s).")
        
        if len(re.findall(AzeliaConfig.SPECIAL_CHARACTERS, password)) < AzeliaConfig.REQUIRE_SPECIAL:
            errors.append(f"Password must contain at least {AzeliaConfig.REQUIRE_SPECIAL} special character(s).")
        
        if errors:
            return False, errors
        return True, []
