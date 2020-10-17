/*
We use Argon2 as the password hashing algorithm -
this is default in the current version of libsodium.
crypto_pwhash_str generates a random salt for each invocation,
concatenates the salt and password and hashes the resulting
string. Argon2 uses a configurable number of hash
iterations (the opslimit parameter) and memory (memlimit)
to make verification respectively more CPU- and RAM-intensive.
The output of crypto_pwhash_str includes the parameters
and salt. These need therefore not be specified when verifying
a password against its hash.
 */

const nacl = require('libsodium-wrappers');

module.exports = async () => {
    await nacl.ready;

};