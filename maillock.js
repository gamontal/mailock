var openpgp = require('openpgp');
var readline = require('readline');
var prompt = require('prompt');


var rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});



function generate_key(ksize, id, pass) {

	var options = {
		numBits: 2048,
		userId: 'Jon Smith ,<jon.smith@someserver.org>',
		passphrase: 'secret stuff'
	};
	
	openpgp.generateKeyPair(options).then(function(keypair) {
		
		var privKey = keypair.privateKeyArmored;
		var pubKey = keypair.publicKeyArmored;
		
		console.log(pubKey);
		
	}).catch(function(error){
		console.log("Error ocurred.");
	});
}




/*

// Encryption

function encrypt() {
	
	var key = "";
	var publicKey = openpgp.key.readArmored(key);
	
	openpgp.encryptMessage(publicKey.keys, "").then(function(pgpMessage){
		// success
	}).catch(function(error) {
		// fail
	});

}

// Decryption
function decrypt() {
	
	var key = '';
	var privateKey = openpgp.key.readArmored(key).keys[0];
	privateKey.decrypt('passphrase');
	
	var pgpMessage = '-----BEGIN PGP MESSAGE ... END PGP MESSAGE-----';
	pgpMessage = openpgp.message.readArmored(pgpMessage);
	
	openpgp.decryptMessage(privateKey, pgpMessage).then(function(plaintext) {
		// success
	}).catch(function(error) {
		// failure
	});
}
*/