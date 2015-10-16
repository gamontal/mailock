#!/usr/bin/env node

'use strict';
var openpgp = require('openpgp'),
	prompt = require('prompt'),
	fs = require('fs'),
	op = require('commander'),
	nodemailer = require('nodemailer'),
	mkdirp = require('mkdirp'),
	colors = require('colors/safe'),
	pjson = require('./package.json'),
	path = require('path');

var base = path.dirname(require.main.filename);
var privatekeyloc = base + '/usr/krg/private/';
var publickeyloc = base + '/usr/krg/public/';

mkdirp(privatekeyloc, function (err) { 
    if (err) {
      console.error(err)
    }
});

mkdirp(publickeyloc, function (err) { 
    if (err) {
      console.error(err)
    }
});

function lst_pub() {
  console.log(lstkey(publickeyloc));
}

function lst_priv() {
  console.log(lstkey(privatekeyloc));
}

function lstkey (dir, files_) {
  files_ = files_ || [];
  var files = fs.readdirSync(dir);

  for (var i in files){
    if((path.extname(files[i]) === ".key") || (path.extname(files[i]) === ".asc")) {
      var name = dir + files[i];
	if (fs.statSync(name).isDirectory()){
	  fs.getFiles(name, files_);
	} else {
	  files_.push(name);
	}
     }
   }
  return files_;
}

function copykfl(source, target, cb) {
  var cbCalled = false;

  var rd = fs.createReadStream(source);
  rd.on("error", function(err) {
    done(err);
  });
  var wr = fs.createWriteStream(target);
  wr.on("error", function(err) {
    done(err);
  });
  wr.on("close", function(ex) {
    done();
  });
  rd.pipe(wr);

  function done(err) {
    if (!cbCalled) {
      cb(err);
      cbCalled = true;
    }
  }
}

function GetFileName(filepath) {
  var base_fl_name = path.basename(filepath);
  var filename = base_fl_name.substr(0, base_fl_name.lastIndexOf('.')) || base_fl_name;
  return filename;
}

function GetExtension(filename) {
    var ext = path.extname(filename||'').split('.');
    return ext[ext.length - 1];
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

        fs.writeFile(privatekeyloc + usrinput.Email + "-private.key", privKey, function(err) {

          if(err) {
            return console.log(err);
          } else {
            console.log("\nYour keys have been generated successfully.\n" + colors.magenta('* Two ' + usrinput.Keylength + "-bit" + ' RSA keys will be stored here: ' + base + '/usr/krg/') + 
                        colors.green('\n* DO NOT LOSE YOUR PRIVATE KEY FILE. If you do, you will lose access to data backed up with this tool and there\'s no way to get them back.\n'));
          }

        });
		
        fs.writeFile(publickeyloc + usrinput.Email + "-public.key", pubKey, function(err) {
			
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

  var pubKeyPath = publickeyloc + eml + "-public.key";
  var filename = GetFileName(filepath);

  fs.stat(pubKeyPath, function(err, stat) { // check if key exists

    if(err === null) {

      var key = fs.readFileSync(pubKeyPath, 'utf8');
      var publicKey = openpgp.key.readArmored(key);

      var message = fs.readFileSync(filepath, "utf8");

      openpgp.encryptMessage(publicKey.keys, message).then(function(pgpMessage){

        fs.writeFile(filename + '.asc', pgpMessage, function(err) {

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

      console.log("\nThe public key was not found. Type --list-public to view available public keys.\n");

    } else {
      console.log(err.code);
    }
  });
}

function decryptfl(eml, filepath) { // filepath == path to the encrypted message

  var privKeyPath = privatekeyloc + eml + "-private.key";

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
            console.log(colors.red('Passphrase is incorrect.'))
          }
        }
      });

    } else if(err.code === 'ENOENT') {
      console.log("\nYour private key was not found. Type --list-private to view available private keys.\n");
    } else {
      console.log(err.code);
    }
  });
}

function signmsg(eml, filepath) {

  var privKeyPath = privatekeyloc + eml + "-private.key";
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

              fs.writeFile("signed-" + filename + ".asc", signedMsg, function(err) {

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
            console.log(colors.red('Passphrase is incorrect.'));
          }
        }
      });

    } else if(err.code === 'ENOENT') {
      console.log("\nYour private key was not found. Type --list-private to view available private keys.\n");
    } else {
      console.log(err.code);
    }
  });
}

function verify_sign(eml, filepath) {

  var pubKeyPath = publickeyloc + eml + "-public.key";
	
  fs.stat(pubKeyPath, function(err, stat) {

    if(err === null) {

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
              console.log("Valid signature: " + valid_message);
            } 
          }
        }
      }).catch(function(err) {
                 console.log(err);
               });	
    } else if(err.code === 'ENOENT') {
      console.log(colors.red("The public key was not found. Type --list-public to view available public keys."));
      process.exit(0);
    } 
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

function import_publickey(publickey) {
  var key_data = fs.readFileSync('./' + publickey, "utf8");
	
  prompt.start();
 
  prompt.get(['Email'], function (err, result) {
    if (err) {
      console.log(err);
    } else {
			
      fs.writeFile(publickeyloc + result.Email + "-public.key", key_data, function(err) {
				
        if(err) {
          return console.log(err);
        }
				
      });
    }
});
	
}

function export_keys(eml) {
  var pubKeyPath = publickeyloc + eml + "-public.key";
  var privKeyPath = privatekeyloc + eml + "-private.key";

  fs.stat(pubKeyPath, function(err, stat) {
    if (err) { console.log("An error ocurred. Public key was not found."); }
    else {
      fs.stat(privKeyPath, function(err, stat) {
        if (err) { console.log("An error ocurred. Private key was not found."); }
        else {
         copykfl(pubKeyPath, "./" + eml + "-public.key", function(err) {
           if (err) { console.log(err); }
         });
         copykfl(privKeyPath, "./" + eml + "-private.key", function(err) {
           if (err) { console.log(err); }
         });
          console.log("Key files have been copied to your current directory");
        }
      });
    }
  });
}

function delete_keys(eml) {
  prompt.start();

  prompt.get({
    properties: {
      cont: {
        required: true,
        description: colors.red("You are about to delete " + eml + "'s key pair.") + "\nContinue? (y/n)?",
        pattern: /^(?:y\b|n\b|Y\b|N\b)/
      }
    }
  }, function(err, response) {
       if (response.cont === "n") {
         process.exit(0);
       } else if (response.cont === "y") {

         var pubKeyPath = publickeyloc + eml + "-public.key";
         var privKeyPath = privatekeyloc + eml + "-private.key";
	
         fs.stat(pubKeyPath, function(err, stat) {
           if (err) { console.log("An error ocurred. Public key was not found.") }
           else {
             fs.stat(privKeyPath, function(err, stat) {
               if (err) { console.log("An error ocurred. Private key was not found.") }
               else {
                 fs.unlinkSync(pubKeyPath);
                 fs.unlinkSync(privKeyPath);
               }
             });
           }
         });
         
       } else if (err) {
         console.log(err);
       }
     });
}

function main() {

  op
  .version(pjson.version)
  .option('-g, --keygen', 'Generate a key pair')
  .option('--list-public', 'output list of saved public keys', lst_pub)
  .option('--list-private', 'output list of saved private keys', lst_priv)
  .option('-i, --import <key>', 'Import a public key file', import_publickey)
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
  .command('delete <email>')
  .description('Delete a user\'s key pair')
  .action(function (email) { 
	  delete_keys(email); 
  });

  op
  .command('export <email>')
  .description('Export a user\'s key pair')
  .action(function (email) { 
	  export_keys(email); 
  });

  op
  .command('send <email> <file>')
  .description('Send email')
  .action(function (email, filename) { 

      var filepath = "./" + filename;
      var file_ext = GetExtension(filepath);

      if (file_ext === "asc") {
        send_mail(email, filepath);
      } else {

        prompt.start();

        prompt.get({
          properties: {
            cont: {
              required: true,
              description: colors.red("This file does not seem to be encrypted. It is strongly recommended that you encrypt confidential data before sending it.") + "\nContinue? (y/n)?",
              pattern: /^(?:y\b|n\b|Y\b|N\b)/
            }
          }
        }, function(err, response) {
			  
             if (response.cont === "n") {
               process.exit(0);
             } else if (response.cont === "y") {
               send_mail(email, filepath); 
             } else if (err) {
               console.log(err);
             } 
           });
      }
    });

  op.parse(process.argv);

  if (op.keygen) { generate_key(); }

}

main();
