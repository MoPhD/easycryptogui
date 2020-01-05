from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def createprivatepublickeypair():
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
	public_key = private_key.public_key()
	
	# PEM or Privacy Enhanced Mail certificates are frequently used for web servers as they can easily be translated
	# into readable data using a simple text editor.  Generally when a PEM encoded file is opened in a text editor, 
	# it contains very distinct headers and footers.
	
	public_pme = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	public_pme.splitlines()[0]
	print(public_pme)
	
	private_pme = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.BestAvailableEncryption(privpass))
	private_pme.splitlines()[0]
	print(private_pme)
	
	return private_key,public_key

def encrypt_using_publickey(myMessage, public_key):
	message = myMessage #This has to be passed from the main page.
	message = message.encode()
	asymmetric_ciphertext = public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	return asymmetric_ciphertext
	
def decrypt_using_privatekey(asymmetric_ciphertext,private_key): 	
	asymmetric_plaintext = private_key.decrypt(asymmetric_ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	asymmetric_plaintext1 = asymmetric_plaintext.decode())
	return asymmetric_plaintext1
