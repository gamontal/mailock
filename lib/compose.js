var nodemailer = require('nodemailer');
var prompt = require('prompt');
var fs = require('fs');

module.exports = function send_mail (eml, filepath) {
  var emlSchema = {
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

  var bodymsg = fs.readFileSync(filepath, 'utf8');

  prompt.get(emlSchema, function (err, result) {
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
      };

      console.log('Sending mail ...');
      transporter.sendMail(message, function (error, info) {
        if (error) {
          console.log('Error occurred');
          console.log(error.message);
          return;
        }
        console.log('Message sent successfully!');
        console.log('Server responded with "%s"', info.response);
      });
    }
  });
};

