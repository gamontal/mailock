var prompt = require('prompt');

module.exports = function compose_email () {
  var info = {
    properties: {
      Password: {
        required: true,
        hidden: true
      },
      To: {
        pattern: /^[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/,
        required: true
      },
      Subject: {
        required: true
      }
    }
  };
  prompt.start();
  return info;
};

