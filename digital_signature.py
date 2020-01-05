from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_der_public_key
import base64
from base64 import (b64encode, b64decode)

from sha3 import sha3hashing
from __main__ import *

# When you call a script, the calling script can access the namespace of the called script. 
# This "from __main__ import *" needs to be in the calling script (AKA the one we want to use the variable in). 
# Note: The star means import anything. To avoid namespace pollution, import the variables you want individually: from __main__ import myMessage.
# The called script is the one holding the variable you want to use. In this case, it would be app.py.

# SENDER: 
# 1.) Generate A Unique Hash Of The Message.
# 2.) Encrypt The Hash Using The Senders Private Key.

# RECIPIENT: 
# 1.) Takes The Received Message & Generates Their Own Hash Of The Message.
# 2.) Decrypts The Received Encrypted Hash (The Senders Hash, Sent Along With The Message) Using The Senders Public Key.

# The recipient compares the hash they generate against the senders decrypted hash; 
# if they match, the message or digital document has not been modified and the sender is authenticated.


def sign_message(message):

	private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
	public_key = private_key.public_key()
	
	# PEM or Privacy Enhanced Mail certificates are frequently used for web servers as they can easily be translated
	# into readable data using a simple text editor.  Generally when a PEM encoded file is opened in a text editor, 
	# it contains very distinct headers and footers.
	
	public_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	
	public_der = b64encode(public_der).decode()
	
	message = bytes(message, 'utf-8')
	signature = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
	
	myDictionary = dict(); 
	myDictionary['Signature:'] = str(b64encode(signature).decode())
	myDictionary['Message'] = str(message.decode())
	myDictionary['Public Key'] = public_der
	
	return (myDictionary)

def verify_digital_signature(received_message, received_encrypted_hash, senders_public_key):
	
	received_message = bytes(received_message, 'utf-8')
	received_encrypted_hash = b64decode(received_encrypted_hash)
	decoded_der = b64decode(senders_public_key)
	
	#1 - Create Hash Of Received Message
	newhash = sha3hashing(str(received_message))
	
	try:
		newkey = load_der_public_key(decoded_der, backend=default_backend())
	
	except:
		return ("Incorrect Public Key!")
		
	else:
	
	#2 - Decrypt Received Encrypted Hash Using Sender's Public Key. (NOTE: If The Public Key Can't Decrypt The Hash, Then The Sender Is Not Verified.)
	# Need To Check For An Error Here If Not Successfully Decrypted.
	
		try:
			newkey.verify(received_encrypted_hash, received_message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
		
		except:
			result2 = "The Decrypted Hash IS NOT The Same As The Hash That You Just Computed: (" + newhash + ") The Sender Is An Imposter!"
			return(result2)
	
		else:
			result1 = "The Decrypted Hash IS The Same As The Hash That You Just Computed: (" + newhash + ") The Sender Has Been Verified!"
			return(result1)


		
