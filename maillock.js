#!/usr/bin/env node

var openpgp = require('openpgp');
var readline = require('readline');
var prompt = require('prompt');
var fs = require('fs');
var op = require('commander');

main();

function generate_key() {
	
	var schema = {
		properties: {
			Keylength: {
				required: true,
				pattern: /^-?\d+\.?\d*$/,
				message: 'Please enter an integer value.'
			},
			Name: {
				pattern: /^[a-zA-Z\s\-]+$/,
				required: true
			},
			Email: {
				required: true,
			},
			Passphrase: {
				required: true,
				hidden: true
			}
		}
	}
	
	prompt.start();
	
	console.log("\n");
	prompt.get(schema, function (err, usrinput) {
	if (!err) {
		var options = {
		numBits: usrinput.Keylength,
		userId: usrinput.Name + " <" + usrinput.Email + ">",
		passphrase: usrinput.Passphrase
	};
	
	openpgp.generateKeyPair(options).then(function(keypair) {
		
		var privKey = keypair.privateKeyArmored; // stores private key value
		var pubKey = keypair.publicKeyArmored;   // stores public key value
		
		fs.writeFile("<" + usrinput.Email + ">" + "private.key", privKey, function(err) {
			if(err) {
				return console.log(err);
			} else {
				console.log("\nYour keys have been generated successfully. \n* As a security measure, make sure you keep your private.key file safe.\n");
			}
		}); 
		
		fs.writeFile("<" + usrinput.Email + ">" + "public.key", pubKey, function(err) {
			if(err) {
				return console.log(err);
			}
		}); 
			
	}).catch(function(error){
		console.log("Error ocurred.");
	});
	
	} else {
		console.log(err);
	}
 });	
}	

// ENCRYPTION
/*
function encrypt(file) {  // takes a file has argument
	
	console.log("Looking for your key ...");
	
	
	
	var key = pubkey;
	var publicKey = openpgp.key.readArmored(key);
	
	openpgp.encryptMessage(publicKey.keys, "").then(function(pgpMessage){
		// success
	}).catch(function(error) {
		// fail
	});
}
  */
// Decryption
/*
function decrypt(privkey) {
	
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

function main() {
	op
  .version('0.0.1')
  .usage('[options] <file ...>')
  .option('-g, --keygen', 'Generate a key pair (They will be saved in your current directory).')
  //.option('-e, --encrypt <f>', 'Encrypt a file.', encrypt)
  .parse(process.argv);
  
  if (op.keygen) {
	  
	  generate_key();
	  
  }  else {
	  
	  console.log("An error ocurred.");
	  
  }
	
}