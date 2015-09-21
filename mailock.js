#!/usr/bin/env node

'use strict';
var openpgp = require('openpgp'),
	readline = require('readline'),
	prompt = require('prompt'),
	fs = require('fs'),
	op = require('commander'),
	nodemailer = require('nodemailer'),
	mkdirp = require('mkdirp'),
	path = require('path');

var base = path.dirname(require.main.filename);
var keyloc = base + '/usr/krg/'; // key pair location

mkdirp(keyloc, function (err) {
    if (err) {
		console.error(err)
	}
});

function lstkey (dir, files_) {
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

function GetFileName(filepath) {
	var base_fl_name = path.basename(filepath);
	var filename = base_fl_name.substr(0, base_fl_name.lastIndexOf('.')) || base_fl_name;
		return filename;
}

function GetPass() {
	
	var UsrPass = {
		properties: {
			Passphrase: {
				required: true,
				hidden: true
			}
		}
	}
	prompt.start();
		return UsrPass;
}

function GetUsrInfo() {
	
	var UserInf = {
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
			return UserInf;
}

function compose_email() {
	
	var emlInf = {
			properties: {
				Password: {
					required: true,
					hidden: true
				},
				To: {
					pattern: /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/,
					required: true
				},
				Subject: {
					required: true
				}
			}
		}
		prompt.start();
			return emlInf;
}

function generate_key() {
	
	var usrinfo = GetUsrInfo();
	
	console.log("\n");
	prompt.get(usrinfo, function (err, usrinput) {
		
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
				console.log("\nYour keys have been generated successfully.\n* As a security measure, make sure you keep a copy of your private.key file safe.\n");
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


function encryptfl(eml, filepath) { // filepath == path to the text file

	var pubKeyPath = keyloc + eml + "-public.key";
	
	var filename = GetFileName(filepath);
	
	fs.stat(pubKeyPath, function(err, stat) { // check if key exists
		
		if(err === null) {
			
			var key = fs.readFileSync(pubKeyPath, 'utf8');
			var publicKey = openpgp.key.readArmored(key);
			
			var message = fs.readFileSync(filepath, "utf8");
			
			openpgp.encryptMessage(publicKey.keys, message).then(function(pgpMessage){
				
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
			
		} else if(err.code === 'ENOENT') { // no keys found
			
			console.log("\nNo keys here. Type --help for information.\n");
			
		} else {
			console.log(err.code);
		}
	});
}

function decryptfl(eml, filepath) { // filepath == path to the encrypted message

	var privKeyPath = keyloc + eml + "-private.key";
	
	fs.stat(privKeyPath, function(err, stat) {
		
		if(err === null) { 
			
			var key = fs.readFileSync(privKeyPath, 'utf8');
			var privateKey = openpgp.key.readArmored(key).keys[0];
			
			var usrpass = GetPass();
			
			prompt.get(usrpass, function (err, result) {
				
				if (err) {
					return console.log(err);
				} else {

					if (privateKey.decrypt(result.Passphrase)) { // validates passpharse
					
					var enc_message = fs.readFileSync(filepath, "utf8");
				    enc_message = openpgp.message.readArmored(enc_message);
					
					
					openpgp.decryptMessage(privateKey, enc_message).then(function(plaintext) {
						console.log(plaintext);
					}).catch(function(error) {
						console.log(error);
					});	 
					
					} else {
						console.log('Passphrase is incorrect.')
					}
				}
			});
				
		} else if(err.code === 'ENOENT') {
			console.log("\nNo keys here.\n");
		} else {
			console.log(err.code);
		}		
	});	
}

function signmsg(eml, filepath) {
	
	var privKeyPath = keyloc + eml + "-private.key";
	
	var filename = GetFileName(filepath);
	
	fs.stat(privKeyPath, function(err, stat) {
		if(err === null) { 
			
			var key = fs.readFileSync(privKeyPath, 'utf8');
			var privateKey = openpgp.key.readArmored(key).keys[0];
			var usrpass = GetPass();
			
			prompt.get(usrpass, function (err, result) {
				
				if (err) {
					
					return console.log(err);
					
				} else {
					
					if (privateKey.decrypt(result.Passphrase)) { // passphrase validation
					var message = fs.readFileSync(filepath, "utf8");

				    openpgp.signClearMessage(privateKey, message).then(function(signedMsg) {
						
						fs.writeFile("signed-" + filename + ".txt", signedMsg, function(err) {
						
						if(err) {
							return console.log(err);
						} else {
							console.log("\nMessage is signed.\n");
						}
						
						});
						
					}).catch(function(error) {
						console.log(error);
					});	
					
					} else {
						console.log('Passphrase is incorrect.');
					}	
				}
			});	
			
		} else if(err.code === 'ENOENT') {
			console.log("\nNo keys here.\n");
		} else {
			console.log(err.code);
		}	
	});
}

function verify_sign(eml, filepath) {
	
	var pubKeyPath = keyloc + eml + "-public.key";
	var key = fs.readFileSync(pubKeyPath, 'utf8');
	
	var publicKey = openpgp.key.readArmored(key).keys[0];
	
	var signedMsg = fs.readFileSync(filepath, "utf8");
	signedMsg = openpgp.cleartext.readArmored(signedMsg);
	
	openpgp.verifyClearSignedMessage(publicKey, signedMsg).then(function(result) {
		
		var valid_message = false;
		
		if ('signatures' in result) {
			var signatures = result['signatures'];
			
			if (signatures.length > 0) {
				var signature = signatures[0];
				
				if ('valid' in signature) {
					valid_message = signature['valid'];
				}
			}
		}
		console.log("Valid signature: " + valid_message);
	}).catch(function(err) {
		console.log(err);
   });	
}

function send_mail(eml, filepath) {
	
	var emlinf = compose_email();
	
	var bodymsg = fs.readFileSync(filepath, "utf8");
	
	prompt.get(emlinf, function (err, result) {
		
		if (err) {
			return console.log(err);
		} else {
		
		var transporter = nodemailer.createTransport({ // SMTP transporter object
			service: 'Gmail',
			auth: {
				user: eml,
				pass: result.Password
			}
		});
		
		console.log('SMTP Configured');

		var message = {
			
			from: eml,
			to: result.To,
			subject: result.Subject,
			text: bodymsg
				
		}

		console.log('Sending mail ...');
		transporter.sendMail(message, function(error, info) {
			if (error) {
				console.log('Error occurred');
				console.log(error.message);
				return;
			}
			console.log('Message sent successfully!');
			console.log('Server responded with "%s"', info.response);
		}); 
		
		}	
	})	
}

function main() {
	
	op
  .version('0.0.1')
  .usage('[option] [command]')
  .option('-g, --keygen', 'Generate a key pair')
  .option('-l, --lstkeys', 'List keyring files, defaults to ~/../mailock/usr/krg/')
  
  	op
  .command('encrypt <email> <file>')
  .description('Encrypt a file')
  .action(function (email, filename) {
	  var filepath = "./" + filename;
	  encryptfl(email, filepath);
  })
  
  	op
  .command('decrypt <email> <file>')
  .description('Decrypt a file')
  .action(function (email, filename) { 
	  var filepath = "./" + filename;
	  decryptfl(email, filepath); 
  });
  
  	op
  .command('sign <email> <file>')
  .description('Sign message')
  .action(function (email, filename) { 
	  var filepath = "./" + filename;
	  signmsg(email, filepath); 
  });
  
    op
  .command('verify <email> <file>')
  .description('Verify Signature')
  .action(function (email, filename) { 
	  var filepath = "./" + filename;
	  verify_sign(email, filepath); 
  });
  
    op
  .command('send <email> <file>')
  .description('Send email')
  .action(function (email, filename) { 
	  var filepath = "./" + filename;
	  send_mail(email, filepath); 
  });
  
  op.parse(process.argv);

  if (op.keygen) { generate_key(); }
  else if (op.lstkeys) { console.log(lstkey(keyloc)); }

}

main();
