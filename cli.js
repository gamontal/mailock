#!/usr/bin/env node

'use strict';
var pkg = require('./package.json');
var fileInfo = require('./lib/file_modules/file_info');
var colors = require('colors/safe');
var prompt = require('prompt');
var fs = require('fs');
var path = require('path');
var mkdirp = require('mkdirp');
var keys = require('./lib/keys');
var encrypt = require('./lib/encryption');
var decrypt = require('./lib/decryption');
var sign = require('./lib/sign');
var verifySign = require('./lib/verify');
var compose = require('./lib/compose');
var cli = require('commander');
var base = path.dirname(require.main.filename);
var privateKeyLoc = base + '/usr/krg/private/';
var publicKeyLoc = base + '/usr/krg/public/';
var filepath;

mkdirp(privateKeyLoc, function (err) {
  if (err) { console.error(err); }
});

mkdirp(publicKeyLoc, function (err) {
  if (err) { console.error(err); }
});

cli
  .version(pkg.version)
  .option('-g, --keygen', 'generate a key pair', keys.generateKeys)
  .option('-i, --import <key>', 'import a public key file', keys.importKey)
  .option('-d, --delete-keys <email>', 'delete a user\'s key pair', keys.deleteKeys)
  .option('-e, --export-keys <email>', 'export a user\'s key pair', keys.exportKeys)
  .option('--list-public', 'output list of saved public keys', keys.listPublic)
  .option('--list-private', 'output list of saved private keys', keys.listPrivate);

cli
  .command('encrypt <email> <file>')
  .description('encrypt a file')
  .action(function (email, filename) {
	  filepath = './' + filename;
	  encrypt(email, filepath, publicKeyLoc);
  });

cli
  .command('decrypt <email> <file>')
  .description('decrypt a file')
  .action(function (email, filename) {
	  filepath = './' + filename;
	  decrypt(email, filepath, privateKeyLoc);
  });

cli
  .command('sign <email> <file>')
  .description('sign message')
  .action(function (email, filename) {
	  filepath = './' + filename;
	  sign(email, filepath, privateKeyLoc);
  });

cli
  .command('verify <email> <file>')
  .description('verify Signature')
  .action(function (email, filename) {
	  filepath = './' + filename;
	  verifySign(email, filepath, publicKeyLoc);
  });

cli
  .command('send <email> <file>')
  .description('send email')
  .action(function (email, filename) {

    filepath = './' + filename;
    var file_ext = fileInfo.GetExtension(filepath);

    if (file_ext === 'asc') {
      compose(email, filepath);
    } else {

      prompt.start();

      prompt.get({
        properties: {
          cont: {
            required: true,
            description: colors.red('This file does not seem to be encrypted. It is strongly recommended that you' +
                                    ' encrypt confidential data before sending it.') + '\nContinue? (y/n)?',
            pattern: /^(?:y\b|n\b|Y\b|N\b)/
          }
        }
      }, function (err, response) {
        if (response.cont === 'n') {
          process.exit(0);
        } else if (response.cont === 'y') {
          compose(email, filepath);
        } else if (err) {
          console.log(err);
        }
      });
    }
  });

cli.parse(process.argv);
if (!process.argv.slice(2).length) { cli.outputHelp(); }

