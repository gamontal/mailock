var openpgp = require('openpgp');
var fileInfo = require('./file_modules/file_info');
var prompt = require('prompt');
var fs = require('fs');
var GetPass = require('./prompt_modules/get_pwd');
var colors = require('colors/safe');

module.exports = function (eml, filepath, privatekeyloc) {
  var privKeyPath = privatekeyloc + eml + '-private.key';
  var filename = fileInfo.GetFileName(filepath);

  fs.stat(privKeyPath, function (err, stat) {
    if (err === null) {
      var key = fs.readFileSync(privKeyPath, 'utf8');
      var privateKey = openpgp.key.readArmored(key).keys[0];
      var usrpass = GetPass();

      prompt.get(usrpass, function (err, result) {
        if (err) {
          return console.log(err);
        } else {
          if (privateKey.decrypt(result.Passphrase)) { // passphrase validation
            var message = fs.readFileSync(filepath, 'utf8');

            openpgp.signClearMessage(privateKey, message).then (function(signedMsg) {
              fs.writeFile('signed-' + filename + '.asc', signedMsg, function (err) {
                if (err) {
                  return console.log(err);
                } else {
                  console.log('\nMessage is signed.\n');
                }
              });
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

