#mailock

####A command-line utility to send encrypted emails via SMTP with OpenPGP.js.

## Installation

`npm install -g mailock`

## Encryption

`mailock encrypt <user@someserver.com> plaintextFile`

## Decryption

`mailock decrypt user@someserver.com encryptedMessage`

## Sign your message

`mailock sign user@someserver.com messagefile`

## Verify signature

`mailock verify user@someserver.com message`

## Third party libraries

All of the project's file security methods are done using the [OpenPGP.js](http://openpgpjs.org) library, and email service with [Nodemailer](http://nodemailer.com/).

For more information on how these libraries work, please check out their GitHub pages:

* [OpenPGP.js](https://github.com/openpgpjs/openpgpjs)
* [Nodemailer](https://github.com/andris9/Nodemailer)
