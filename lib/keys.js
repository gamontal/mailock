var openpgp = require('openpgp');
var prompt = require('prompt');
var fs = require('fs');
var colors = require('colors/safe');
var path = require('path');
var base = path.dirname(require.main.filename);
var privatekeyloc = base + '/data/usr/krg/private/';
var publickeyloc = base + '/data/usr/krg/public/';
var mkdirp = require('mkdirp');


function copyKey (source, target, cb) {
  var cbCalled = false;
  var rd = fs.createReadStream(source);
  rd.on('error', function (err) {
    done(err);
  });

  var wr = fs.createWriteStream(target);
  wr.on('error', function (err) {
    done(err);
  });

  wr.on('close', function (ex) {
    done();
  });

  rd.pipe(wr);

  function done (err) {
    if (!cbCalled) {
      cb(err);
      cbCalled = true;
    }
  }
}

function list (dir, files_) {
  files_ = files_ || [];
  var files = fs.readdirSync(dir);

  for (var i in files) {
    if((path.extname(files[i]) === '.key') || (path.extname(files[i]) === '.asc')) {
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

module.exports = {

  generateKeys: function () {
    var usr = {
      properties: {
        keylength: {
          required: true,
          pattern: /^-?\d+\.?\d*$/,
          message: 'Please enter an integer value.'
        },
        name: {
          pattern: /^[a-zA-Z\s\-]+$/,
          required: true
        },
        email: {
          // RFC 2822 standard
          pattern: /^[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?/,
          required: true
        },
        passphrase: {
          required: true,
          hidden: true
        }
      }
    };
    console.log('');

    prompt.start();
    prompt.get(usr, function (err, usr) {
      if (err) {
        console.log(err);
      } else {
        var options = {
          numBits: usr.keylength,
          userId: usr.name + '<' + usr.email + '>',
          passphrase: usr.passphrase
        };

        openpgp.generateKeyPair(options).then(function (keypair) {
          var privKey = keypair.privateKeyArmored;
          var pubKey = keypair.publicKeyArmored;

          fs.writeFile(publickeyloc + usr.email + '-public.key', pubKey, function (err) {
            if (err) {
              return console.log(err);
            }
          });

          fs.writeFile(privatekeyloc + usr.email + '-private.key', privKey, function (err) {
            if (err) {
              return console.log(err);
            } else {
              console.log('\nYour keys have been generated successfully.\n' +
                          colors.magenta('* Two ' + usr.keylength + "-bit" + ' RSA keys will be stored here: ' +
                                         base + '/usr/krg/') +
                          colors.green('\n* DO NOT LOSE YOUR PRIVATE KEY FILE. ' +
                                       'If you do, you will lose access to data backed up with this tool and' +
                                       ' there\'s no way to get them back.\n'));
            }
          });

        }).catch(function (error){
          console.log(err);
        });

      }
    });
  },

  listPublic: function () {
    console.log(list(publickeyloc));
  },

  listPrivate: function () {
    console.log(list(privatekeyloc));
  },

  exportKeys: function (eml) {
    var pubKeyPath = publickeyloc + eml + '-public.key';
    var privKeyPath = privatekeyloc + eml + '-private.key';

    fs.stat(pubKeyPath, function (err, stat) {
      if (err) { console.log('An error ocurred. Public key was not found.'); }
      else {
        fs.stat(privKeyPath, function (err, stat) {
          if (err) { console.log('An error ocurred. Private key was not found.'); }
          else {
            copyKey(pubKeyPath, './' + eml + '-public.key', function (err) {
              if (err) { console.log(err); }
            });
            copyKey(privKeyPath, "./" + eml + '-private.key', function (err) {
              if (err) { console.log(err); }
            });
            console.log('Your keys have been copied to your current directory');
          }
        });
      }
    });
  },

  importKey: function (pk) {
    var key_data = fs.readFileSync('./' + publickey, 'utf8');

    prompt.start();
    prompt.get(['Email'], function (err, result) {
      if (err) {
        console.log(err);
      } else {

        fs.writeFile(publickeyloc + result.Email + '-public.key', key_data, function (err) {
          if (err) {
            return console.log(err);
          }
        });
      }
    });
  },

  deleteKeys: function (eml) {
    prompt.start();

    prompt.get({
      properties: {
        cont: {
          required: true,
          description: colors.red('You are about to delete ' + eml + '\'s key pair.') + '\nContinue? (y/n)?',
          pattern: /^(?:y\b|n\b|Y\b|N\b)/
        }
      }
    }, function (err, response) {
      if (response.cont === 'n') {
        process.exit(0);
      } else if (response.cont === 'y') {

        var pubKeyPath = publickeyloc + eml + '-public.key';
        var privKeyPath = privatekeyloc + eml + '-private.key';

        fs.stat(pubKeyPath, function (err, stat) {
          if (err) { console.log('An error ocurred. Public key was not found.'); }
          else {
            fs.stat(privKeyPath, function (err, stat) {
              if (err) { console.log('An error ocurred. Private key was not found.'); }
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
};

