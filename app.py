from flask import Flask, render_template, request, flash
from config import Config 
import sys
import hashlib
import sha3
import symmetric_scheme
import digital_signature

app = Flask(__name__) # __name__ is a special variable in python. It's the name of the module.
app.config.from_object(Config)

@app.route("/") # Routes are what we type to go to different pages. Contact pages, etc. The forward slash is the root page of our website.  
def main():
	return render_template('index.html') # We want to return the main page here, the HTML index page. The forward slash is the root page of our website.

@app.route("/showSend")
def showSend():
	return render_template('index.html') # This render_template is a function that must be imported. It allows us to specify an HTML file to render when that route / URL is visited.

@app.route("/showReceive")
def showReceive():
	return render_template('receive.html')

@app.route('/secure', methods=['GET', 'POST'])
def secure():

	message = request.form['message']
	encryption_password = request.form['encryption_password']
	
	if request.form.get('hash'):			#If the Hash Button is Checked, Return The Result Of The SHA3 Hash Function.
		return(sha3.sha3hashing(message))
		
	if request.form.get('encrypt'):			#If the Encrypt Button is Checked, Return The Result Of The SYMMETRIC Hash Function.
		return "Encrypted Message: {}".format(symmetric_scheme.generateSymmetricKey2(message, encryption_password))
		
	if request.form.get('sign'):
		return(digital_signature.sign_message(message))

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
	
	encrypted_message = request.form['encrypted_message']
	symmetric_key = request.form['symmetric_key']

	return(symmetric_scheme.symmetricDecrypt(encrypted_message, symmetric_key))

@app.route('/verify_hash', methods=['GET', 'POST'])
def verify_hash():
	
	myreceived_message = request.form['myreceived_message']
	received_hash = request.form['received_hash']
	
	return(sha3.verify_sha3hash(myreceived_message, received_hash))


@app.route('/verify_signature', methods=['GET', 'POST'])
def verify_signature():

	received_message = request.form['received_message']
	received_encrypted_hash = request.form['received_encrypted_hash']
	senders_public_key = request.form['senders_public_key']
	
	return(digital_signature.verify_digital_signature(received_message, received_encrypted_hash, senders_public_key))

if __name__ == "__main__":  #This code makes it so that you don't have to use "Flask Run" to start the server. You can just run the python script directly: "python3 app.py"
	app.run(debug=True)	# This makes it so that you don't have to set environment variable "export FLASK_DEBUG=1". So you don't have to stop/start your web server every time a change is made.
		
		
#Any request made to the server is logged in the command window. It will show everything, successes or failures, 200s or 404s or whatever.


