var openpgp = require('openpgp');
var fs = require('fs');
var GetPass = require('./prompt_modules/get_pwd');
var prompt = require('prompt');
var colors = require('colors/safe');

module.exports = function(eml, filepath, privatekeyloc) {
   var privKeyPath = privatekeyloc + eml + '-private.key';

  fs.stat(privKeyPath, function (err, stat) {
    if(err === null) {
      var key = fs.readFileSync(privKeyPath, 'utf8');
      var privateKey = openpgp.key.readArmored(key).keys[0];

      var usrpass = GetPass();

      prompt.get(usrpass, function (err, result) {
        if (err) {
          return console.log(err);
        } else {
          if (privateKey.decrypt(result.Passphrase)) { // validates passpharse
            var enc_message = fs.readFileSync(filepath, 'utf8');
            enc_message = openpgp.message.readArmored(enc_message);

            openpgp.decryptMessage(privateKey, enc_message).then(function (plaintext) {
              console.log(plaintext);
            }).catch(function (error) {
              console.log(error);
            });

          } else {
            console.log(colors.red('Passphrase is incorrect.'));
          }
        }
      });
    } else if (err.code === 'ENOENT') {
      console.log('\nYour private key was not found. Type --list-private to view available private keys.\n');
    } else {
      console.log(err.code);
    }
  });
};

