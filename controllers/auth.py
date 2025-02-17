import bcrypt

class Authenticator:
    def __init__(self):
        pass
    def hash_password(self,password:str) -> bytes:
        password = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password,salt)
        return hashed_password

    def check_password(self, password:str, hashed_password:bytes)-> bool:
        password_bytes = password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_password)
    

if __name__ == "__main__":
    auth = Authenticator()
    password = input()
    

    hashed_password = auth.hash_password(password)
    print("Хэшированный пароль:", hashed_password)
    
    
    is_valid = auth.check_password(password, hashed_password)
    print("Пароль верный:", is_valid)