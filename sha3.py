import sys
import hashlib
from __main__ import *
# When you call a script, the calling script can access the namespace of the called script. 
# This "from __main__ import *" needs to be in the calling script (AKA the one we want to use the variable in). 
# Note: The star means import anything. To avoid namespace pollution, import the variables you want individually: from __main__ import myMessage.
# The called script is the one holding the variable you want to use. In this case, it would be app.py.

def sha3hashing(message):
	#myMessage = input("Please Enter Message To Be Hashed: ")
	s = hashlib.sha3_256(message.encode('utf-8')) # SHA3_224, SHA3_384, & SHA3_512 Are Other Options.
	SHA3_HASH = s.hexdigest()
	return(SHA3_HASH)
	#print(s.hexdigest())
	
def verify_sha3hash(myreceived_message, received_hash):
	#myMessage = input("Please Enter Message To Be Hashed: ")
	s = hashlib.sha3_256(myreceived_message.encode('utf-8')) # SHA3_224, SHA3_384, & SHA3_512 Are Other Options.
	SHA3_HASH = s.hexdigest()
	
	if SHA3_HASH == received_hash:
		identicalhashes = "The Received Hash: " + received_hash + "    Your Computed Hash: " + SHA3_HASH + " Are IDENTICAL. THE MESSAGE IS THE SAME AS HOW THE SENDER SENT IT."
		return (identicalhashes)
	
	if SHA3_HASH != received_hash:
		messagehasbeentampered = "The Received Hash: " + received_hash + "    Your Computed Hash: " + SHA3_HASH + " Are DIFFERENT. THE MESSAGE HAS BEEN TAMPERED WITH."
		return(messagehasbeentampered)
