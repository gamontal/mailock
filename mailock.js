#!/usr/bin/env node

var openpgp = require('openpgp'),
	readline = require('readline'),
	prompt = require('prompt'),
	fs = require('fs'),
	op = require('commander'),
	path = require("path");

main();

function getk (dir, files_) {
    files_ = files_ || [];
    var files = fs.readdirSync(dir);
		for (var i in files){
			if(path.extname(files[i]) === ".key") {
				var name = dir + '/' + files[i];
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
		
		var kpth = path.join('usr','krg/');
		var privKey = keypair.privateKeyArmored; 
		var pubKey = keypair.publicKeyArmored;   
		
		fs.writeFile(kpth + usrinput.Email + "-private.key", privKey, function(err) {
			
			if(err) {
				return console.log(err);
			} else {
				console.log("\nYour keys have been generated successfully. \n* As a security measure, make sure you keep your private.key file safe.\n");
			}
			
		}); 
		
		fs.writeFile(kpth + usrinput.Email + "-public.key", pubKey, function(err) {
			
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


function encryptfl(usrEmail, filename) { 
	
	console.log("Looking for your key ...\n");
	
	var eml = usrEmail;
	var txtFile = filename;
	
	var pubKeyPath = path.join('usr','krg/') + eml + "-public.key";
	
	fs.stat(pubKeyPath, function(err, stat) {
		if(err === null) {
			
			var key = fs.readFileSync(pubKeyPath, 'utf8');
			
			var testtext = "This is a normal sentence.";
			
			console.log(txtFile);
			console.log('...\n');
			
			var publickey = openpgp.key.readArmored(key);
			
			openpgp.encryptMessage(publickey, testtext).then(function(pgpMessage){
					console.log(pgpMessage);
				}).catch(function(error) {
					console.log(err);
				}); 
			
		} else if(err.code === 'ENOENT') {
			console.log("No keys here.");
		} else {
			console.log('Some other error: ', err.code);
		}
	});
}

function main() {
	
	op
  .version('0.0.1')
  .option('-g, --keygen', 'Generate a key pair (They will be saved in your current directory).')
  .option('--listkeys', 'List keyring files.')
  .command('encrypt <email> [file]')
  .action(function (email, filename) { 
	  encryptfl(email, filename); 
  });

  op.parse(process.argv);

  if (op.keygen) { generate_key(); }
  else if (op.listkeys) { console.log(getk(path.join('usr','krg'))); }

}