var openpgp = require('openpgp');
var fs = require('fs');
var colors = require('colors/safe');


module.exports = function verify_sign (eml, filepath, publickeyloc) {
  var pubKeyPath = publickeyloc + eml + '-public.key';

  fs.stat(pubKeyPath, function(err, stat) {

    if (err === null) {
      var key = fs.readFileSync(pubKeyPath, 'utf8');
      var publicKey = openpgp.key.readArmored(key).keys[0];
      var signedMsg = fs.readFileSync(filepath, 'utf8');
      signedMsg = openpgp.cleartext.readArmored(signedMsg);

      openpgp.verifyClearSignedMessage(publicKey, signedMsg).then(function (result) {
        var valid_message = false;

        if ('signatures' in result) {
          var signatures = result.signatures;

          if (signatures.length > 0) {
            var signature = signatures[0];

            if ('valid' in signature) {
              valid_message = signature.valid;
              console.log('Valid signature: ' + valid_message);
            }
          }
        }
      }).catch(function (err) {
        console.log(err);
      });
    } else if (err.code === 'ENOENT') {
      console.log(colors.red('The public key was not found. Type --list-public to view available public keys.'));
      process.exit(0);
    }
  });
};
