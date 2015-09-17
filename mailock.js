#!/usr/bin/env node

'use strict';
var openpgp = require('openpgp'),
	readline = require('readline'),
	prompt = require('prompt'),
	fs = require('fs'),
	op = require('commander'),
	path = require("path");




var base = path.dirname(require.main.filename);
var keyloc = base + '/usr/krg/'; // key pair location

main();

function getk (dir, files_) {
    files_ = files_ || [];
    var files = fs.readdirSync(dir);
		for (var i in files){
			if(path.extname(files[i]) === ".key") {
				var name = dir + files[i];
				if (fs.statSync(name).isDirectory()){
					getFiles(name, files_);
				} else {
					files_.push(name);
				}
			}
        }
  return files_;
} 

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
				// RFC 2822 standard
				pattern: /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/,
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
		userId: usrinput.Name + "<" + usrinput.Email + ">",
		passphrase: usrinput.Passphrase
	};
	
	openpgp.generateKeyPair(options).then(function(keypair) {
		
		var privKey = keypair.privateKeyArmored; 
		var pubKey = keypair.publicKeyArmored;   
		
		fs.writeFile(keyloc + usrinput.Email + "-private.key", privKey, function(err) {
			
			if(err) {
				return console.log(err);
			} else {
				console.log("\nYour keys have been generated successfully. \n* As a security measure, make sure you keep your private.key file safe.\n");
			}
			
		}); 
		
		fs.writeFile(keyloc + usrinput.Email + "-public.key", pubKey, function(err) {
			
			if(err) {
				return console.log(err);
			}
			
		}); 
			
		}).catch(function(error){
			console.log(err);
		});
	
	} else {
		console.log(err);
	}
 });	
}	


function encryptfl(usrEmail, filepath) { 
	
	console.log("\nLooking for your key ...\n");
	
	var eml = usrEmail;
	
	var base_fl_name = path.basename(filepath);
	var filename = base_fl_name.substr(0, base_fl_name.lastIndexOf('.')) || base_fl_name;
	
	var pubKeyPath = keyloc + eml + "-public.key";
	
	fs.stat(pubKeyPath, function(err, stat) {
		
		if(err === null) {
			
			var key = fs.readFileSync(pubKeyPath, 'utf8');
			var publicKey = openpgp.key.readArmored(key);
			
			openpgp.encryptMessage(publicKey.keys, filepath).then(function(pgpMessage){
				
				fs.writeFile("encrypted-" + filename + '.asc', pgpMessage, function(err) {
				
					if(err) {
						
						return console.log(err);
						
					} else {
						console.log("\nEncryption was successful.\n");
					}
			
				}); 
						
			}).catch(function(error) {
				console.log(err);
			}); 
			
		} else if(err.code === 'ENOENT') {
			
			console.log("No keys here.\n");
			
		} else {
			console.log(err.code);
		}
	});
}

/*
function decryptfl(usrEmail, filepath) {
	
	console.log("\nLooking for your key ...\n");
	
	var eml = usrEmail;
	var flpath = filepath; // encrypted message
	
	var privKeyPath = path.join('usr','krg/') + eml + "-private.key";

	fs.stat(privKeyPath, function(err, stat) {
		if(err === null) {
		
			var key = fs.readFileSync(privKeyPath, 'utf8');
			var pgpMessage = fs.readFileSync(flpath, 'utf8');
			
			var privateKey = openpgp.key.readArmored(key).keys[0];

			var schema = {
				properties: {
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
					var passwd = {
					passphrase: usrinput.Passphrase
					}
				};	
				
				privateKey.decrypt(passwd.passphrase); 
				
				pgpMessage = openpgp.message.readArmored(pgpMessage);
				
				openpgp.decryptMessage(privateKey, pgpMessage).then(function(plaintext) {
					
					console.log(plaintext);
					
				}).catch(function(error) {
					
					console.log(err);
				
				});
					
			});
		
		} else if(err.code === 'ENOENT') {
			console.log("No keys here.\n");
		} else {
			console.log('Some other error: ', err.code);
		}
		
	});
}
 */ 

function main() {
	
	op
  .version('0.0.1')
  .usage('[option]')
  .option('-g, --keygen', 'Generate a key pair')
  .option('--listkeys', 'List keyring files')
  
  	op
  .command('encrypt <email> [file]')
  .description('Encrypt a file')
  .action(function (email, filename) { 
	  var filepth = "./" + filename;
	  encryptfl(email, filepth); 
  })
  
  /*	op
  .command('decrypt <email> [file]')
  .description('Decrypt a file')
  .action(function (email, filename) { 
	  var filepth = "./" + filename;
	  decryptfl(email, filepth); 
  });
*/
  op.parse(process.argv);

  if (op.keygen) { generate_key(); }
  else if (op.listkeys) { console.log(getk(keyloc)); }

}
