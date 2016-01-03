var prompt = require('prompt');

module.exports = function GetPass () {
  var UsrPass = {
    properties: {
      Passphrase: {
        required: true,
        hidden: true
      }
    }
  };
  prompt.start();
  return UsrPass;
};
