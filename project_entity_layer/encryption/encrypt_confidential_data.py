import io

from passlib.hash import pbkdf2_sha256

import os,sys

from cryptography.fernet import Fernet
import uuid
class EncryptData:
    def __init__(self):
        pass

    def get_encrypted_text(self,text):
        """
        This function will return hash calcualted on your data
        :param data:
        :return encrypted hash:
        """
        try:

            if text is not None:
                hash = pbkdf2_sha256.hash(text)
                return hash

        except Exception as e:
            print(e)




    def verify_encrypted_text(self,text,encrypted_text):
        try:
            return pbkdf2_sha256.verify(text, encrypted_text)
        except Exception as e:
            pass



    def generate_key(self,):
        """
        Generates a key and save it into a file
        """
        key = Fernet.generate_key()
        #with open("secret.key", "wb") as key_file:
            #key_file.write(key)
        key=key.decode('utf-8')
        return key

    def load_key(self):
        """

        :return:
        """
        #key = os.environ.get('SECRET_KEY_MONGO_DB', None)
        #key=key.encode('utf-8')
        key='TkN-wphtDLwMLYQCjspoAbu66T6Q24Oo9Y1yBIEOiik='

        return key


    def encrypt_message(self,message,key=None):
        """
        Encrypts a message
        """

        encoded_message = message.encode()
        if key is None:
            key=self.load_key()
        #print(key)
        f = Fernet(key)
        encrypted_message = f.encrypt(encoded_message)

        #print(encrypted_message)
        return encrypted_message

    def decrypt_message(self,encrypted_message,key=None):
        """
        Decrypts an encrypted message
        """
        if key is None:
            key=self.load_key()
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message



