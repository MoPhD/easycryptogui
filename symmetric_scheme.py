from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
import base64
import sys
from __main__ import *
import hashlib

# When you call a script, the calling script can access the namespace of the called script. 
# This "from __main__ import *" needs to be in the calling script (AKA the one we want to use the variable in). 
# Note: The star means import anything. To avoid namespace pollution, import the variables you want individually: from __main__ import myMessage.
# The called script is the one holding the variable you want to use. In this case, it would be app.py.

def generateSymmetricKey2(message, encryption_password):
	# We Are Asking A User For A Password. We Will Use It As A Seed.
	# We Then Generate a Key From The Password. The key From The Pass Is Just A Salted Hash.

	
	encpass = encryption_password.encode()
	data = message.encode()
	
	m = hashlib.sha3_256()
	m.update(encpass)
	key = base64.urlsafe_b64encode(m.digest())
	f = Fernet(key)
	ct = f.encrypt(data)
	return(ct.decode())


    
    
def symmetricDecrypt(encrypted_message, symmetric_key):
    
	ct = encrypted_message.encode()
	key = symmetric_key.encode()
	m = hashlib.sha3_256()
	m.update(key)
	key = base64.urlsafe_b64encode(m.digest())
	
	f = Fernet(key)
	
	try:
		f.decrypt(ct)
	
	except:
		return("The Password Is Incorrect!")
	
	else:
		return f.decrypt(ct)
		
		
