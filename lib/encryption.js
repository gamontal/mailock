var openpgp = require('openpgp');
var fs = require('fs');
var fileInfo = require('./file_modules/file_info');

module.exports = function(eml, filepath, publickeyloc) {
  var pubKeyPath = publickeyloc + eml + '-public.key';
  var filename = fileInfo.GetFileName(filepath);

  fs.stat(pubKeyPath, function (err, stat) {
    if(err === null) {
      var key = fs.readFileSync(pubKeyPath, 'utf8');
      var publicKey = openpgp.key.readArmored(key);

      var message = fs.readFileSync(filepath, 'utf8');

      openpgp.encryptMessage(publicKey.keys, message).then(function (pgpMessage){

        fs.writeFile(filename + '.asc', pgpMessage, function (err) {
          if(err) {
            return console.log(err);
          } else {
            console.log('\nEncryption was successful.\n');
          }
        });
      }).catch(function (error) {
        console.log(err);
      });
    } else if(err.code === 'ENOENT') {
      console.log('\nThe public key was not found. Type --list-public to display your public keys.\n');
    } else {
      console.log(err.code);
    }
  });
};

